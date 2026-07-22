// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{net::SocketAddr, sync::Arc};

use blockgen::BlockGeneratorTestApi;
use cfx_rpc_cfx_api::TestRpcServer;
use cfx_rpc_cfx_types::{
    blame_info::BlameInfo, block::Block, pos::Block as PosBlock, Bytes,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::internal_error_with_data;
use cfx_types::{H256, U256, U64};
use cfxcore::{
    consensus::pos_handler::PosVerifier, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use diem_types::{
    account_address::AccountAddress, transaction::TransactionPayload,
};
use jsonrpsee::{
    core::RpcResult,
    types::{
        error::{INVALID_PARAMS_CODE, METHOD_NOT_FOUND_CODE},
        ErrorObjectOwned,
    },
};
use log::info;
use network::{node_table::NodeId, NetworkService, PeerInfo};
use parking_lot::{Condvar, Mutex};
use primitives::{SignedTransaction, TransactionWithSignature};
use random_crash::*;
use rlp::Rlp;
use txgen::{DirectTransactionGenerator, TransactionGenerator};

use crate::common::CommonRpcImpl;

pub struct TestHandler {
    common: CommonRpcImpl,
    block_gen: BlockGeneratorTestApi,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    sync: SharedSynchronizationService,
}

impl TestHandler {
    pub fn new(
        exit: Arc<(Mutex<bool>, Condvar)>, consensus: SharedConsensusGraph,
        network: Arc<NetworkService>, pos_handler: Arc<PosVerifier>,
        tx_pool: SharedTransactionPool, accounts: Arc<AccountProvider>,
        block_gen: BlockGeneratorTestApi,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
        sync: SharedSynchronizationService,
    ) -> Self {
        let common = CommonRpcImpl::new(
            exit,
            consensus,
            network,
            tx_pool,
            accounts,
            pos_handler,
        );
        TestHandler {
            common,
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
}

impl TestRpcServer for TestHandler {
    fn say_hello(&self) -> RpcResult<String> { self.common.say_hello() }

    fn get_block_count(&self) -> RpcResult<u64> {
        self.common.get_block_count()
    }

    fn get_goodput(&self) -> RpcResult<String> { self.common.get_goodput() }

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
        self.common.add_peer(id, addr)
    }

    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()> {
        self.common.drop_peer(id, addr)
    }

    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        self.common.get_peer_info()
    }

    fn chain(&self) -> RpcResult<Vec<Block>> { self.common.chain() }

    fn stop(&self) -> RpcResult<()> { self.common.stop() }

    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        self.common.get_nodeid(challenge)
    }

    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        self.common.add_latency(id, latency_ms)
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
                        self.common.consensus.best_chain_id().in_native_space(),
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
        let consensus_graph = &*self.common.consensus;
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
        self.common
            .consensus
            .inner
            .read()
            .get_pivot_chain_and_weight(height_range)
            .map_err(internal_error_with_data)
    }

    fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)> {
        let commitment = self
            .common
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

    fn save_node_db(&self) -> RpcResult<()> { self.common.save_node_db() }

    fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> RpcResult<(Bytes, AccountAddress)> {
        self.common.pos_register(voting_power, version)
    }

    fn pos_update_voting_power(
        &self, pos_account: AccountAddress, increased_voting_power: U64,
    ) -> RpcResult<()> {
        self.common
            .pos_update_voting_power(pos_account, increased_voting_power)
    }

    fn pos_stop_election(&self) -> RpcResult<Option<u64>> {
        self.common.pos_stop_election()
    }

    fn pos_start_voting(&self, initialize: bool) -> RpcResult<()> {
        self.common.pos_start_voting(initialize)
    }

    fn pos_stop_voting(&self) -> RpcResult<()> { self.common.pos_stop_voting() }

    fn pos_voting_status(&self) -> RpcResult<bool> {
        self.common.pos_voting_status()
    }

    fn pos_start(&self) -> RpcResult<()> { self.common.pos_start() }

    fn pos_force_vote_proposal(&self, block_id: H256) -> RpcResult<()> {
        self.common.pos_force_vote_proposal(block_id)
    }

    fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> RpcResult<()> {
        self.common
            .pos_force_propose(round, parent_block_id, payload)
    }

    fn pos_trigger_timeout(&self, timeout_type: String) -> RpcResult<()> {
        self.common.pos_trigger_timeout(timeout_type)
    }

    fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> RpcResult<()> {
        self.common
            .pos_force_sign_pivot_decision(block_hash, height)
    }

    fn pos_get_chosen_proposal(&self) -> RpcResult<Option<PosBlock>> {
        self.common.pos_get_chosen_proposal()
    }
}
