// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use blockgen::BlockGeneratorTestApi;
use cfx_rpc_cfx_api::TestRpcServer;
use cfx_rpc_cfx_types::{
    blame_info::BlameInfo,
    block::{Block, BlockTransactions},
    pos::{Block as PosBlock, Decision},
    receipt::Receipt,
    transaction::{PackedOrExecuted, Transaction as RpcTransaction},
    Block as RpcBlock, Bytes,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    internal_error, internal_error_with_data,
};
use cfx_types::{Space, H256, U256, U64};
use cfxcore::{
    block_data_manager::{BlockDataManager, DataVersionTuple},
    consensus::{pos_handler::PosVerifier, ConsensusGraphInner},
    genesis_block::register_transaction,
    pow, SharedConsensusGraph, SharedSynchronizationService,
};
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    block_info::PivotBlockDecision,
    transaction::TransactionPayload,
};
use jsonrpsee::{
    core::RpcResult,
    types::{
        error::{
            INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE,
        },
        ErrorObjectOwned,
    },
};
use log::{info, warn};
use network::{
    node_table::{NodeEndpoint, NodeEntry, NodeId},
    NetworkService, PeerInfo,
};
use parking_lot::{Condvar, Mutex};
use primitives::{
    Block as PrimitiveBlock, SignedTransaction, TransactionIndex,
    TransactionStatus, TransactionWithSignature,
};
use random_crash::*;
use rlp::Rlp;
use txgen::{DirectTransactionGenerator, TransactionGenerator};

use crate::hash_value_to_h256;

pub struct TestHandler {
    exit: Arc<(Mutex<bool>, Condvar)>,
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    network: Arc<NetworkService>,
    pos_handler: Arc<PosVerifier>,
    block_gen: BlockGeneratorTestApi,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    sync: SharedSynchronizationService,
}

impl TestHandler {
    pub fn new(
        exit: Arc<(Mutex<bool>, Condvar)>, consensus: SharedConsensusGraph,
        network: Arc<NetworkService>, pos_handler: Arc<PosVerifier>,
        block_gen: BlockGeneratorTestApi,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
        sync: SharedSynchronizationService,
    ) -> Self {
        let data_man = consensus.data_manager().clone();
        TestHandler {
            exit,
            consensus,
            data_man,
            network,
            pos_handler,
            block_gen,
            maybe_txgen,
            maybe_direct_txgen,
            sync,
        }
    }

    fn decode_raw_txs(
        &self, raw_txs: Bytes, tx_data_len: usize,
    ) -> RpcResult<Vec<Arc<SignedTransaction>>> {
        let txs: Vec<TransactionWithSignature> =
            Rlp::new(&raw_txs.into_vec()).as_list().map_err(|err| {
                ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    format!("raw_txs decode error: {:?}", err),
                    None::<()>,
                )
            })?;

        let mut transactions = Vec::new();

        for tx in txs {
            let public = match tx.recover_public() {
                Ok(public) => public,
                Err(e) => {
                    return Err(ErrorObjectOwned::owned(
                        INVALID_PARAMS_CODE,
                        format!("Recover public error: {:?}", e),
                        None::<()>,
                    ));
                }
            };

            let mut signed_tx = SignedTransaction::new(public, tx);

            if tx_data_len > 0 {
                *signed_tx.transaction.transaction.unsigned.data_mut() =
                    vec![0; tx_data_len];
            }

            transactions.push(Arc::new(signed_tx));
        }

        Ok(transactions)
    }

    fn build_rpc_block(
        &self, b: &PrimitiveBlock, consensus_inner: &ConsensusGraphInner,
        include_txs: bool,
    ) -> Result<RpcBlock, String> {
        let network = *self.network.get_network_type();
        let block_hash = b.block_header.hash();

        let epoch_number = consensus_inner
            .get_block_epoch_number(&block_hash)
            .or_else(|| self.data_man.block_epoch_number(&block_hash))
            .map(Into::into);

        let block_number = self
            .consensus
            .get_block_number(&block_hash)?
            .map(Into::into);

        let _tx_len = b.transactions.len();

        let (gas_used, transactions) = {
            let maybe_results = consensus_inner
                .block_execution_results_by_hash(&b.hash(), false);

            let gas_used_sum = match maybe_results {
                Some(DataVersionTuple(_, ref execution_result)) => {
                    let mut total_gas_used = U256::zero();
                    let mut prev_acc_gas_used = U256::zero();
                    for (idx, tx) in b.transactions.iter().enumerate() {
                        let receipt =
                            &execution_result.block_receipts.receipts[idx];
                        if tx.space() == Space::Native {
                            total_gas_used += receipt.accumulated_gas_used
                                - prev_acc_gas_used;
                        }
                        prev_acc_gas_used = receipt.accumulated_gas_used;
                    }
                    Some(total_gas_used)
                }
                None => None,
            };

            let transactions = match include_txs {
                false => BlockTransactions::Hashes(
                    b.transaction_hashes(Some(Space::Native)),
                ),
                true => {
                    let maybe_results = consensus_inner
                        .block_execution_results_by_hash(&b.hash(), false);
                    let tx_vec = match maybe_results {
                        Some(DataVersionTuple(_, ref execution_result)) => {
                            let maybe_state_root = self
                                .data_man
                                .get_executed_state_root(&b.hash());

                            b.transactions
                                .iter()
                                .enumerate()
                                .filter(|(_idx, tx)| {
                                    tx.space() == Space::Native
                                })
                                .enumerate()
                                .map(|(new_index, (original_index, tx))| {
                                    let receipt = execution_result
                                        .block_receipts
                                        .receipts
                                        .get(original_index)
                                        .unwrap();
                                    let prior_gas_used =
                                        if original_index == 0 {
                                            U256::zero()
                                        } else {
                                            execution_result
                                                .block_receipts
                                                .receipts[original_index - 1]
                                                .accumulated_gas_used
                                        };
                                    match receipt.outcome_status {
                                        TransactionStatus::Success
                                        | TransactionStatus::Failure => {
                                            let tx_index = TransactionIndex {
                                                block_hash: b.hash(),
                                                real_index: original_index,
                                                is_phantom: false,
                                                rpc_index: Some(new_index),
                                            };
                                            let tx_exec_error_msg =
                                                &execution_result
                                                    .block_receipts
                                                    .tx_execution_error_messages
                                                    [original_index];
                                            RpcTransaction::from_signed(
                                                tx,
                                                Some(
                                                    PackedOrExecuted::Executed(
                                                        Receipt::new(
                                                            (**tx).clone(),
                                                            receipt.clone(),
                                                            tx_index,
                                                            prior_gas_used,
                                                            epoch_number,
                                                            execution_result
                                                                .block_receipts
                                                                .block_number,
                                                            b.block_header
                                                                .base_price(),
                                                            maybe_state_root,
                                                            if tx_exec_error_msg
                                                                .is_empty()
                                                            {
                                                                None
                                                            } else {
                                                                Some(
                                                                    tx_exec_error_msg
                                                                        .clone(),
                                                                )
                                                            },
                                                            network,
                                                            false,
                                                            false,
                                                        )?,
                                                    ),
                                                ),
                                                network,
                                            )
                                        }
                                        TransactionStatus::Skipped => {
                                            RpcTransaction::from_signed(
                                                tx, None, network,
                                            )
                                        }
                                    }
                                })
                                .collect::<Result<_, _>>()?
                        }
                        None => b
                            .transactions
                            .iter()
                            .filter(|tx| tx.space() == Space::Native)
                            .map(|x| {
                                RpcTransaction::from_signed(x, None, network)
                            })
                            .collect::<Result<_, _>>()?,
                    };
                    BlockTransactions::Full(tx_vec)
                }
            };

            (gas_used_sum, transactions)
        };

        let base_fee_per_gas: Option<U256> =
            b.block_header.base_price().map(|x| x[Space::Native]).into();
        let gas_limit: U256 = b.block_header.core_space_gas_limit();

        Ok(RpcBlock {
            hash: H256::from(block_hash),
            parent_hash: H256::from(b.block_header.parent_hash().clone()),
            height: b.block_header.height().into(),
            miner: cfx_rpc_cfx_types::address::RpcAddress::try_from_h160(
                *b.block_header.author(),
                network,
            )?,
            deferred_state_root: H256::from(
                b.block_header.deferred_state_root().clone(),
            ),
            deferred_receipts_root: H256::from(
                b.block_header.deferred_receipts_root().clone(),
            ),
            deferred_logs_bloom_hash: H256::from(
                b.block_header.deferred_logs_bloom_hash().clone(),
            ),
            blame: U64::from(b.block_header.blame()),
            transactions_root: H256::from(
                b.block_header.transactions_root().clone(),
            ),
            epoch_number: epoch_number.map(|e| U256::from(e)),
            block_number,
            gas_used,
            gas_limit,
            base_fee_per_gas,
            timestamp: b.block_header.timestamp().into(),
            difficulty: b.block_header.difficulty().clone().into(),
            pow_quality: b
                .block_header
                .pow_hash
                .map(|h| pow::pow_hash_to_quality(&h, &b.block_header.nonce())),
            adaptive: b.block_header.adaptive(),
            referee_hashes: b
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| H256::from(*x))
                .collect(),
            nonce: b.block_header.nonce().into(),
            transactions,
            custom: b
                .block_header
                .custom()
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            size: Some(b.size().into()),
            pos_reference: b.block_header.pos_reference().clone(),
        })
    }
}

impl TestRpcServer for TestHandler {
    fn say_hello(&self) -> RpcResult<String> { Ok("Hello, world".into()) }

    fn get_block_count(&self) -> RpcResult<u64> {
        info!("RPC Request: get_block_count()");
        let count = self.consensus.block_count();
        info!("RPC Response: get_block_count={}", count);
        Ok(count)
    }

    fn get_goodput(&self) -> RpcResult<String> {
        info!("RPC Request: get_goodput");
        let mut all_block_set = HashSet::new();
        for epoch_number in 1..self.consensus.best_epoch_number() {
            for block_hash in self
                .consensus
                .get_block_hashes_by_epoch(epoch_number.into())
                .map_err(|_| internal_error())?
            {
                all_block_set.insert(block_hash);
            }
        }
        let mut set = HashSet::new();
        let mut min = std::u64::MAX;
        let mut max: u64 = 0;
        for key in &all_block_set {
            if let Some(block) =
                self.data_man.block_by_hash(key, false /* update_cache */)
            {
                let timestamp = block.block_header.timestamp();
                if timestamp < min && timestamp > 0 {
                    min = timestamp;
                }
                if timestamp > max {
                    max = timestamp;
                }
                for transaction in &block.transactions {
                    set.insert(transaction.hash());
                }
            }
        }
        if max != min {
            let lower_bound = min + ((max - min) as f64 * 0.3) as u64;
            let upper_bound = min + ((max - min) as f64 * 0.8) as u64;
            let mut ranged_set = HashSet::new();
            for key in &all_block_set {
                if let Some(block) = self
                    .data_man
                    .block_by_hash(key, false /* update_cache */)
                {
                    let timestamp = block.block_header.timestamp();
                    if timestamp > lower_bound && timestamp < upper_bound {
                        for transaction in &block.transactions {
                            ranged_set.insert(transaction.hash());
                        }
                    }
                }
            }
            if upper_bound != lower_bound {
                Ok(format!(
                    "full: {}, ranged: {}",
                    set.len() as isize / (max - min) as isize,
                    ranged_set.len() as isize
                        / (upper_bound - lower_bound) as isize
                ))
            } else {
                Ok(format!(
                    "full: {}",
                    set.len() as isize / (max - min) as isize
                ))
            }
        } else {
            Ok("-1".to_string())
        }
    }

    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>> {
        info!("RPC Request: generate({:?})", num_blocks);
        let max_block_size = self
            .sync
            .get_synchronization_graph()
            .verification_config
            .max_block_size_in_bytes;
        let mut hashes = Vec::new();
        for _i in 0..num_blocks {
            hashes.push(self.block_gen.generate_block(
                0,
                max_block_size,
                vec![],
            ));
        }
        Ok(hashes)
    }

    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>,
    ) -> RpcResult<H256> {
        info!(
            "RPC Request: generate_fixed_block({:?}, {:?}, {:?}, {:?}, {:?})",
            parent_hash, referee, num_txs, difficulty, pos_reference,
        );
        self.block_gen
            .generate_fixed_block(
                parent_hash,
                referee,
                num_txs,
                difficulty.unwrap_or(0),
                adaptive,
                pos_reference,
            )
            .map_err(internal_error_with_data)
    }

    fn add_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()> {
        let node = NodeEntry {
            id,
            endpoint: NodeEndpoint {
                address: addr,
                udp_port: addr.port(),
            },
        };
        info!("RPC Request: add_peer({:?})", node.clone());
        self.network.add_peer(node).map_err(|_| internal_error())
    }

    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()> {
        let node = NodeEntry {
            id,
            endpoint: NodeEndpoint {
                address: addr,
                udp_port: addr.port(),
            },
        };
        info!("RPC Request: drop_peer({:?})", node.clone());
        self.network.drop_peer(node).map_err(|_| internal_error())
    }

    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        info!("RPC Request: get_peer_info");
        Ok(self.network.get_peer_info().unwrap_or_default())
    }

    fn chain(&self) -> RpcResult<Vec<Block>> {
        info!("RPC Request: test_getChain");
        let consensus_graph = &*self.consensus;
        let inner = &*consensus_graph.inner.read();

        let result: Result<Vec<_>, String> = inner
            .all_blocks_with_topo_order()
            .iter()
            .map(|hash| {
                let block = self
                    .data_man
                    .block_by_hash(hash, false /* update_cache */)
                    .expect("Error to get block by hash");
                self.build_rpc_block(&*block, inner, true)
            })
            .collect();

        result.map_err(|e| {
            ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, e, None::<()>)
        })
    }

    fn stop(&self) -> RpcResult<()> {
        *self.exit.0.lock() = true;
        self.exit.1.notify_all();
        Ok(())
    }

    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        self.network
            .sign_challenge(challenge)
            .map_err(|_| internal_error())
    }

    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        self.network
            .add_latency(id, latency_ms)
            .map_err(|_| internal_error())
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_one_block()");
        Ok(self
            .block_gen
            .generate_block(num_txs, block_size_limit, vec![]))
    }

    fn generate_one_block_with_direct_txgen(
        &self, num_txs: usize, mut block_size_limit: usize,
        num_txs_simple: usize, num_txs_erc20: usize,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_one_block_with_direct_txgen()");
        match self.maybe_direct_txgen.as_ref() {
            None => Err(ErrorObjectOwned::owned(
                METHOD_NOT_FOUND_CODE,
                "generate_one_block_with_direct_txgen only allowed in test or dev mode.",
                None::<()>,
            )),
            Some(direct_txgen) => {
                let generated_transactions =
                    direct_txgen.lock().generate_transactions(
                        &mut block_size_limit,
                        num_txs_simple,
                        num_txs_erc20,
                        self.consensus.best_chain_id().in_native_space(),
                    );
                Ok(self.block_gen.generate_block(
                    num_txs,
                    block_size_limit,
                    generated_transactions,
                ))
            }
        }
    }

    fn generate_custom_block(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes,
        adaptive: Option<bool>, custom: Option<Vec<Bytes>>,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_custom_block()");
        let transactions = self.decode_raw_txs(raw, 0)?;
        self.block_gen
            .generate_custom_block_with_parent(
                parent,
                referees,
                transactions,
                adaptive.unwrap_or(false),
                custom.map(|list| {
                    list.into_iter().map(|bytes| bytes.0).collect()
                }),
            )
            .map_err(internal_error_with_data)
    }

    fn generate_block_with_fake_txs(
        &self, raw: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>,
    ) -> RpcResult<H256> {
        let transactions =
            self.decode_raw_txs(raw, tx_data_len.unwrap_or(0))?;
        Ok(self.block_gen.generate_custom_block(transactions, adaptive))
    }

    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256> {
        Ok(self.block_gen.generate_block_with_blame_info(
            num_txs,
            block_size_limit,
            vec![],
            blame_info.blame.map(|x| x.as_u32()),
            blame_info.deferred_state_root.map(|x| x.into()),
            blame_info.deferred_receipts_root.map(|x| x.into()),
            blame_info.deferred_logs_bloom_hash.map(|x| x.into()),
        ))
    }

    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256> {
        let transactions = self.decode_raw_txs(raw, 0)?;
        self.block_gen
            .generate_block_with_nonce_and_timestamp(
                parent,
                referees,
                transactions,
                nonce,
                timestamp,
                adaptive,
            )
            .map_err(internal_error_with_data)
    }

    fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)> {
        let consensus_graph = &*self.consensus;
        let status = consensus_graph
            .data_man
            .local_block_info_by_hash(&block_hash)
            .ok_or(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "No block status",
                None::<()>,
            ))?
            .get_status();
        let state_valid = consensus_graph
            .inner
            .read()
            .block_node(&block_hash)
            .ok_or(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "No block in consensus",
                None::<()>,
            ))?
            .data
            .state_valid
            .ok_or(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "No state_valid",
                None::<()>,
            ))?;
        Ok((status.to_db_status(), state_valid))
    }

    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()> {
        self.sync.expire_block_gc(timeout);
        Ok(())
    }

    fn get_pivot_chain_and_weight(
        &self, height_range: Option<(u64, u64)>,
    ) -> RpcResult<Vec<(H256, U256)>> {
        self.consensus
            .inner
            .read()
            .get_pivot_chain_and_weight(height_range)
            .map_err(internal_error_with_data)
    }

    fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)> {
        let commitment = self
            .consensus
            .data_manager()
            .get_epoch_execution_commitment(&block_hash)
            .ok_or(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "No receipts root. Possibly never pivot?",
                None::<()>,
            ))?;
        Ok((
            commitment.receipts_root.clone().into(),
            commitment
                .state_root_with_aux_info
                .state_root
                .compute_state_root_hash(),
        ))
    }

    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes> {
        info!(
            "RPC Request: send_usable_genesis_accounts start from {:?}",
            account_start_index
        );
        match self.maybe_txgen.as_ref() {
            None => Err(ErrorObjectOwned::owned(
                METHOD_NOT_FOUND_CODE,
                "send_usable_genesis_accounts only allowed in test or dev mode with txgen set.",
                None::<()>,
            )),
            Some(txgen) => {
                txgen.set_genesis_accounts_start_index(account_start_index);
                Ok(Bytes::new("1".into()))
            }
        }
    }

    fn set_db_crash(
        &self, crash_probability: f64, crash_exit_code: i32,
    ) -> RpcResult<()> {
        if crash_probability == 0.0 {
            *CRASH_EXIT_PROBABILITY.lock() = None;
        } else {
            *CRASH_EXIT_PROBABILITY.lock() = Some(crash_probability);
        }
        *CRASH_EXIT_CODE.lock() = crash_exit_code;
        Ok(())
    }

    fn save_node_db(&self) -> RpcResult<()> {
        self.network.save_node_db();
        Ok(())
    }

    fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> RpcResult<(Bytes, AccountAddress)> {
        let legacy = version.map_or(false, |x| x == 0);
        let tx = register_transaction(
            self.pos_handler.config().bls_key.private_key(),
            self.pos_handler.config().vrf_key.public_key(),
            voting_power.as_u64(),
            0,
            legacy,
        );
        let identifier = from_consensus_public_key(
            &self.pos_handler.config().bls_key.public_key(),
            &self.pos_handler.config().vrf_key.public_key(),
        );
        Ok((tx.data.into(), identifier))
    }

    fn pos_update_voting_power(
        &self, _pos_account: AccountAddress, _increased_voting_power: U64,
    ) -> RpcResult<()> {
        unimplemented!()
    }

    fn pos_stop_election(&self) -> RpcResult<Option<u64>> {
        self.pos_handler.stop_election().map_err(|e| {
            warn!("stop_election: err={:?}", e);
            internal_error()
        })
    }

    fn pos_start_voting(&self, initialize: bool) -> RpcResult<()> {
        info!("RPC Request: pos_start_voting, initialize={}", initialize);
        self.pos_handler.start_voting(initialize).map_err(|e| {
            warn!("start_voting: err={:?}", e);
            internal_error_with_data(e.to_string())
        })
    }

    fn pos_stop_voting(&self) -> RpcResult<()> {
        info!("RPC Request: pos_stop_voting");
        self.pos_handler.stop_voting().map_err(|e| {
            warn!("stop_voting: err={:?}", e);
            internal_error_with_data(e.to_string())
        })
    }

    fn pos_voting_status(&self) -> RpcResult<bool> {
        self.pos_handler.voting_status().map_err(|e| {
            warn!("voting_status: err={:?}", e);
            internal_error_with_data(e.to_string())
        })
    }

    fn pos_start(&self) -> RpcResult<()> {
        self.pos_handler
            .initialize(self.consensus.clone())
            .map_err(internal_error_with_data)
    }

    fn pos_force_vote_proposal(&self, block_id: H256) -> RpcResult<()> {
        if !self.network.is_test_mode() {
            return Err(internal_error());
        }
        self.pos_handler.force_vote_proposal(block_id).map_err(|e| {
            warn!("force_vote_proposal: err={:?}", e);
            internal_error()
        })
    }

    fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> RpcResult<()> {
        if !self.network.is_test_mode() {
            return Err(internal_error());
        }
        self.pos_handler
            .force_propose(round, parent_block_id, payload)
            .map_err(|e| {
                warn!("pos_force_propose: err={:?}", e);
                internal_error()
            })
    }

    fn pos_trigger_timeout(&self, timeout_type: String) -> RpcResult<()> {
        if !self.network.is_test_mode() {
            return Err(internal_error());
        }
        self.pos_handler.trigger_timeout(timeout_type).map_err(|e| {
            warn!("pos_trigger_timeout: err={:?}", e);
            internal_error()
        })
    }

    fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> RpcResult<()> {
        if !self.network.is_test_mode() {
            return Err(internal_error());
        }
        self.pos_handler
            .force_sign_pivot_decision(PivotBlockDecision {
                block_hash,
                height: height.as_u64(),
            })
            .map_err(|e| {
                warn!("pos_force_sign_pivot_decision: err={:?}", e);
                internal_error()
            })
    }

    fn pos_get_chosen_proposal(&self) -> RpcResult<Option<PosBlock>> {
        let maybe_block = self
            .pos_handler
            .get_chosen_proposal()
            .map_err(|e| {
                warn!("pos_get_chosen_proposal: err={:?}", e);
                internal_error()
            })?
            .and_then(|b| {
                let block_hash = b.id();
                self.pos_handler
                    .cached_db()
                    .get_block(&block_hash)
                    .ok()
                    .map(|executed_block| {
                        let executed_block = executed_block.lock();
                        PosBlock {
                            hash: hash_value_to_h256(b.id()),
                            epoch: U64::from(b.epoch()),
                            round: U64::from(b.round()),
                            last_tx_number: executed_block
                                .output()
                                .version()
                                .unwrap_or_default()
                                .into(),
                            miner: b.author().map(|a| H256::from(a.to_u8())),
                            parent_hash: hash_value_to_h256(b.parent_id()),
                            timestamp: U64::from(b.timestamp_usecs()),
                            pivot_decision: executed_block
                                .output()
                                .pivot_block()
                                .as_ref()
                                .map(|d| Decision::from(d)),
                            height: executed_block
                                .output()
                                .executed_trees()
                                .pos_state()
                                .current_view()
                                .into(),
                            signatures: vec![],
                        }
                    })
            });
        Ok(maybe_block)
    }
}
