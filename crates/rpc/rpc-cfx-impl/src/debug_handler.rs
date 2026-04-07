// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::BTreeMap, sync::Arc};

use cfx_addr::Network;
use cfx_rpc_cfx_api::DebugRpcServer;
use cfx_rpc_cfx_types::{
    address::check_rpc_address_network,
    consensus_graph_states::{
        ConsensusGraphBlockExecutionState, ConsensusGraphBlockState,
    },
    sync_graph_states::SyncGraphBlockState,
    ConsensusGraphStates, EpochNumber, RpcAddress, StatOnGasLoad,
    SyncGraphStates, Transaction as RpcTransaction,
};
use cfx_rpc_eth_types::{Transaction as EthTransaction, WrapTransaction};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    internal_error_with_data, invalid_params_rpc_err,
};
use cfx_types::{Address, AddressSpaceUtil, Space, H256, U64};
use cfx_util_macros::bail;
use cfxcore::{
    block_data_manager::{BlockDataManager, BlockExecutionResult},
    state_exposer::STATE_EXPOSER,
    ConsensusGraph, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use jsonrpsee::core::RpcResult;
use log::debug;
use network::{
    node_table::{Node, NodeId},
    throttling::{self, THROTTLING_SERVICE},
    NetworkService, SessionDetails, UpdateNodeOperation,
};
use primitives::{
    Action, Block, EpochNumber as PrimitiveEpochNumber, SignedTransaction,
    TransactionIndex, TransactionStatus,
};

use cfx_rpc_cfx_types::{
    receipt::Receipt as RpcReceipt, transaction::PackedOrExecuted,
};

pub struct DebugHandler {
    tx_pool: SharedTransactionPool,
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    sync: SharedSynchronizationService,
    network: Arc<NetworkService>,
    network_type: Network,
}

impl DebugHandler {
    pub fn new(
        tx_pool: SharedTransactionPool, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, network: Arc<NetworkService>,
    ) -> Self {
        let data_man = consensus.data_manager().clone();
        let network_type = *network.get_network_type();
        DebugHandler {
            tx_pool,
            consensus,
            data_man,
            sync,
            network,
            network_type,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph { &self.consensus }

    fn check_address_network(&self, address: &RpcAddress) -> RpcResult<()> {
        check_rpc_address_network(Some(address.network), &self.network_type)
            .map_err(|e| invalid_params_rpc_err(e.to_string(), None::<bool>))
    }

    fn get_block_epoch_number(&self, h: &H256) -> Option<u64> {
        if let Some(e) = self.consensus.get_block_epoch_number(h) {
            return Some(e);
        }
        self.data_man.block_epoch_number(h)
    }

    fn get_transactions(
        &self, blocks: &[Arc<Block>], pivot: &Arc<Block>, epoch_number: u64,
    ) -> RpcResult<Vec<WrapTransaction>> {
        let mut transactions = vec![];
        for b in blocks.iter() {
            let mut txs =
                self.get_transactions_for_block(b, pivot, epoch_number)?;
            transactions.append(&mut txs);
        }
        Ok(transactions)
    }

    fn get_transactions_for_block(
        &self, b: &Arc<Block>, pivot: &Arc<Block>, epoch_number: u64,
    ) -> RpcResult<Vec<WrapTransaction>> {
        let exec_info =
            self.data_man.block_execution_result_by_hash_with_epoch(
                &b.hash(),
                &pivot.hash(),
                false,
                false,
            );
        if let Some(execution_result) = exec_info {
            self.get_transactions_for_executed_block(
                b,
                pivot,
                epoch_number,
                execution_result,
            )
            .map_err(|e| internal_error_with_data(e))
        } else {
            self.get_transactions_for_non_executed_block(b, pivot)
                .map_err(|e| internal_error_with_data(e))
        }
    }

    fn get_transactions_for_non_executed_block(
        &self, b: &Arc<Block>, pivot: &Arc<Block>,
    ) -> Result<Vec<WrapTransaction>, String> {
        let network = self.network_type;

        let mut eth_transaction_idx = 0u64;
        let mut make_eth_wrap_tx = |tx: &Arc<SignedTransaction>| {
            let block_info = (
                Some(pivot.hash()),
                Some(pivot.block_header.height().into()),
                Some(eth_transaction_idx.into()),
            );
            eth_transaction_idx += 1;
            WrapTransaction::EthTransaction(EthTransaction::from_signed(
                tx,
                block_info,
                (None, None),
            ))
        };

        let make_cfx_wrap_tx =
            |tx: &Arc<SignedTransaction>| -> Result<WrapTransaction, String> {
                Ok(WrapTransaction::NativeTransaction(
                    RpcTransaction::from_signed(tx, None, network)?,
                ))
            };

        let mut res = vec![];
        for tx in b.transactions.iter() {
            res.push(match tx.space() {
                Space::Ethereum => make_eth_wrap_tx(tx),
                Space::Native => make_cfx_wrap_tx(tx)?,
            });
        }
        Ok(res)
    }

    fn get_transactions_for_executed_block(
        &self, b: &Arc<Block>, pivot: &Arc<Block>, epoch_number: u64,
        execution_result: BlockExecutionResult,
    ) -> Result<Vec<WrapTransaction>, String> {
        let network = self.network_type;
        let maybe_state_root = self.data_man.get_executed_state_root(&b.hash());
        let block_receipts = &execution_result.block_receipts.receipts;

        let mut eth_transaction_idx = 0u64;
        let mut make_eth_wrap_tx = |tx: &Arc<SignedTransaction>, id: usize| {
            let receipt = &block_receipts[id];
            let status = receipt.outcome_status.in_space(Space::Ethereum);
            let contract_address =
                match status == primitives::receipt::EVM_SPACE_SUCCESS {
                    true => EthTransaction::deployed_contract_address(tx),
                    false => None,
                };
            let block_info = (
                Some(pivot.hash()),
                Some(pivot.block_header.height().into()),
                Some(eth_transaction_idx.into()),
            );
            eth_transaction_idx += 1;
            WrapTransaction::EthTransaction(EthTransaction::from_signed(
                tx,
                block_info,
                (Some(status.into()), contract_address),
            ))
        };

        let mut cfx_transaction_index = 0usize;
        let mut make_cfx_wrap_tx = |tx: &Arc<SignedTransaction>,
                                    id: usize|
         -> Result<WrapTransaction, String> {
            let receipt = &block_receipts[id];
            let prior_gas_used = if id == 0 {
                cfx_types::U256::zero()
            } else {
                block_receipts[id - 1].accumulated_gas_used
            };

            if receipt.outcome_status == TransactionStatus::Skipped {
                cfx_transaction_index += 1;
                return Ok(WrapTransaction::NativeTransaction(
                    RpcTransaction::from_signed(tx, None, network)?,
                ));
            }

            let tx_index = TransactionIndex {
                block_hash: b.hash(),
                real_index: id,
                is_phantom: false,
                rpc_index: Some(cfx_transaction_index),
            };
            let tx_exec_error_msg = &execution_result
                .block_receipts
                .tx_execution_error_messages[id];
            let rpc_receipt = RpcReceipt::new(
                (**tx).clone(),
                receipt.clone(),
                tx_index,
                prior_gas_used,
                Some(epoch_number),
                execution_result.block_receipts.block_number,
                b.block_header.base_price(),
                maybe_state_root,
                if tx_exec_error_msg.is_empty() {
                    None
                } else {
                    Some(tx_exec_error_msg.clone())
                },
                network,
                false,
                false,
            )?;
            cfx_transaction_index += 1;
            let executed = Some(PackedOrExecuted::Executed(rpc_receipt));
            Ok(WrapTransaction::NativeTransaction(
                RpcTransaction::from_signed(tx, executed, network)?,
            ))
        };

        let mut res = vec![];
        for (id, tx) in b.transactions.iter().enumerate() {
            res.push(match tx.space() {
                Space::Ethereum => make_eth_wrap_tx(tx, id),
                Space::Native => make_cfx_wrap_tx(tx, id)?,
            });
        }
        Ok(res)
    }
}

fn grouped_txs<T, F>(
    txs: Vec<Arc<SignedTransaction>>, converter: F,
) -> BTreeMap<String, BTreeMap<usize, Vec<T>>>
where F: Fn(Arc<SignedTransaction>) -> T {
    let mut addr_grouped_txs: BTreeMap<String, BTreeMap<usize, Vec<T>>> =
        BTreeMap::new();

    for tx in txs {
        let addr = format!("{:?}", tx.sender());
        let addr_entry =
            addr_grouped_txs.entry(addr).or_insert_with(BTreeMap::new);
        let nonce = tx.nonce().as_usize();
        let nonce_entry = addr_entry.entry(nonce).or_insert_with(Vec::new);
        nonce_entry.push(converter(tx));
    }

    addr_grouped_txs
}

impl DebugRpcServer for DebugHandler {
    fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        let address: Option<Address> = match address {
            None => None,
            Some(addr) => {
                self.check_address_network(&addr)?;
                Some(addr.into())
            }
        };

        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(address.map(AddressSpaceUtil::with_native_space));

        let converter = |tx: Arc<SignedTransaction>| -> String {
            let to = match tx.action() {
                Action::Create => "<Create contract>".into(),
                Action::Call(addr) => format!("{:?}", addr),
            };
            format!(
                "{}: {:?} drip + {:?} gas * {:?} drip",
                to,
                tx.value(),
                tx.gas(),
                tx.gas_price()
            )
        };

        let mut ret: BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<String>>>,
        > = BTreeMap::new();
        ret.insert("ready".into(), grouped_txs(ready_txs, converter));
        ret.insert("deferred".into(), grouped_txs(deferred_txs, converter));
        Ok(ret)
    }

    fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        let address: Option<Address> = match address {
            None => None,
            Some(addr) => {
                self.check_address_network(&addr)?;
                Some(addr.into())
            }
        };

        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(address.map(AddressSpaceUtil::with_native_space));

        let network = self.network_type;
        let converter = |tx: Arc<SignedTransaction>| -> RpcTransaction {
            RpcTransaction::from_signed(&tx, None, network)
                .expect("transaction conversion with correct network id should not fail")
        };

        let mut ret: BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        > = BTreeMap::new();
        ret.insert("ready".into(), grouped_txs(ready_txs, converter));
        ret.insert("deferred".into(), grouped_txs(deferred_txs, converter));
        Ok(ret)
    }

    fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> RpcResult<Vec<RpcTransaction>> {
        self.check_address_network(&address)?;
        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(Some(Address::from(address).with_native_space()));
        let network = self.network_type;
        let converter = |tx: &Arc<SignedTransaction>| {
            RpcTransaction::from_signed(tx, None, network)
        };
        let result = ready_txs
            .iter()
            .map(converter)
            .chain(deferred_txs.iter().map(converter))
            .collect::<Result<_, _>>()
            .map_err(|e| internal_error_with_data(e))?;
        Ok(result)
    }

    fn txpool_clear(&self) -> RpcResult<()> {
        self.tx_pool.clear_tx_pool();
        Ok(())
    }

    fn net_throttling(&self) -> RpcResult<throttling::Service> {
        Ok(THROTTLING_SERVICE.read().clone())
    }

    fn net_node(&self, node_id: NodeId) -> RpcResult<Option<(String, Node)>> {
        match self.network.get_node(&node_id) {
            None => Ok(None),
            Some((trusted, node)) => {
                if trusted {
                    Ok(Some(("trusted".into(), node)))
                } else {
                    Ok(Some(("untrusted".into(), node)))
                }
            }
        }
    }

    fn net_disconnect_node(
        &self, id: NodeId, op: Option<UpdateNodeOperation>,
    ) -> RpcResult<bool> {
        Ok(self.network.disconnect_node(&id, op))
    }

    fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>> {
        match self.network.get_detailed_sessions(node_id) {
            None => Ok(Vec::new()),
            Some(sessions) => Ok(sessions),
        }
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        Ok(self.sync.current_sync_phase().name().into())
    }

    fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates> {
        let consensus_graph_states =
            STATE_EXPOSER.consensus_graph.lock().retrieve();

        let block_state_vec = consensus_graph_states
            .block_state_vec
            .iter()
            .map(|s| ConsensusGraphBlockState {
                block_hash: s.block_hash.into(),
                best_block_hash: s.best_block_hash.into(),
                block_status: (s.block_status as u8).into(),
                era_block_hash: s.era_block_hash.into(),
                adaptive: s.adaptive,
            })
            .collect();

        let block_execution_state_vec = consensus_graph_states
            .block_execution_state_vec
            .iter()
            .map(|s| ConsensusGraphBlockExecutionState {
                block_hash: s.block_hash.into(),
                deferred_state_root: s.deferred_state_root.into(),
                deferred_receipt_root: s.deferred_receipt_root.into(),
                deferred_logs_bloom_hash: s.deferred_logs_bloom_hash.into(),
                state_valid: s.state_valid,
            })
            .collect();

        Ok(ConsensusGraphStates {
            block_state_vec,
            block_execution_state_vec,
        })
    }

    fn sync_graph_state(&self) -> RpcResult<SyncGraphStates> {
        let sync_graph_states = STATE_EXPOSER.sync_graph.lock().retrieve();
        let ready_block_vec = sync_graph_states
            .ready_block_vec
            .into_iter()
            .map(|s| SyncGraphBlockState {
                block_hash: s.block_hash.into(),
                parent: s.parent.into(),
                referees: s.referees.iter().map(|x| H256::from(*x)).collect(),
                nonce: s.nonce.into(),
                timestamp: U64::from(s.timestamp),
                adaptive: s.adaptive,
            })
            .collect();
        Ok(SyncGraphStates { ready_block_vec })
    }

    fn stat_on_gas_load(
        &self, last_epoch: EpochNumber, time_window: U64,
    ) -> RpcResult<Option<StatOnGasLoad>> {
        let mut stat = StatOnGasLoad::default();
        stat.time_elapsed = time_window;

        let block_not_found_error = || {
            internal_error_with_data(
                "Cannot find the block by a ConsensusGraph provided hash",
            )
        };

        let machine = self.tx_pool.machine();
        let consensus = self.consensus_graph();

        let mut epoch_number = match last_epoch {
            EpochNumber::Earliest => {
                bail!(invalid_params_rpc_err(
                    "Cannot stat genesis",
                    None::<bool>
                ))
            }
            EpochNumber::Num(num) if num.is_zero() => {
                bail!(invalid_params_rpc_err(
                    "Cannot stat genesis",
                    None::<bool>
                ))
            }
            EpochNumber::LatestMined => bail!(invalid_params_rpc_err(
                "Epoch number is earlier than 'latest_state'",
                None::<bool>
            )),
            EpochNumber::Num(num) => {
                let pivot_hash = consensus
                    .get_hash_from_epoch_number(
                        PrimitiveEpochNumber::LatestState,
                    )
                    .map_err(|e| internal_error_with_data(e.to_string()))?;
                let latest_epoch = consensus
                    .get_block_epoch_number(&pivot_hash)
                    .ok_or_else(block_not_found_error)?;
                if latest_epoch < num.as_u64() {
                    bail!(invalid_params_rpc_err(
                        "Epoch number is earlier than 'latest_state'",
                        None::<bool>
                    ))
                }
                num.as_u64()
            }
            EpochNumber::LatestCheckpoint
            | EpochNumber::LatestFinalized
            | EpochNumber::LatestConfirmed
            | EpochNumber::LatestState => {
                let pivot_hash = consensus
                    .get_hash_from_epoch_number(last_epoch.into_primitive())
                    .map_err(|e| internal_error_with_data(e.to_string()))?;
                consensus
                    .get_block_epoch_number(&pivot_hash)
                    .ok_or_else(block_not_found_error)?
            }
        };

        let mut last_timestamp: Option<u64> = None;

        loop {
            let block_hashes = consensus
                .get_block_hashes_by_epoch(PrimitiveEpochNumber::Number(
                    epoch_number,
                ))
                .map_err(|e| internal_error_with_data(e.to_string()))?;
            let blocks = consensus
                .data_manager()
                .blocks_by_hash_list(&block_hashes, false)
                .ok_or_else(block_not_found_error)?;
            let pivot_block = blocks.last().ok_or_else(|| {
                internal_error_with_data("Epoch without block")
            })?;

            let timestamp = pivot_block.block_header.timestamp();
            if last_timestamp.is_none() {
                last_timestamp = Some(timestamp);
            }
            if last_timestamp.unwrap().saturating_sub(time_window.as_u64())
                > timestamp
            {
                break;
            }

            let params = machine.params();
            stat.epoch_num += 1.into();
            for b in &blocks {
                stat.total_block_num += 1.into();
                stat.total_gas_limit += *b.block_header.gas_limit();
                if params.can_pack_evm_transaction(b.block_header.height()) {
                    stat.espace_block_num += 1.into();
                    stat.espace_gas_limit += *b.block_header.gas_limit()
                        / params.evm_transaction_gas_ratio;
                }
            }

            for b in &blocks {
                let exec_info =
                    match consensus.get_block_execution_info(&b.hash()) {
                        None => bail!(internal_error_with_data(
                        "Cannot fetch block receipt with checked input params"
                    )),
                        Some((res, _)) => res.1,
                    };

                for (receipt, tx) in exec_info
                    .block_receipts
                    .receipts
                    .iter()
                    .zip(&b.transactions)
                {
                    let space = tx.space();
                    if receipt.outcome_status == TransactionStatus::Skipped {
                        *stat.skipped_tx_count.in_space_mut(space) += 1.into();
                        *stat.skipped_tx_gas_limit.in_space_mut(space) +=
                            *tx.gas_limit();
                    } else {
                        *stat.confirmed_tx_count.in_space_mut(space) +=
                            1.into();
                        *stat.confirmed_tx_gas_limit.in_space_mut(space) +=
                            *tx.gas_limit();
                        *stat.tx_gas_charged.in_space_mut(space) +=
                            receipt.gas_fee / tx.gas_price();
                    }
                }
            }

            if epoch_number > 0 {
                epoch_number -= 1;
            } else {
                break;
            }
        }

        Ok(Some(stat))
    }

    fn transactions_by_epoch(
        &self, epoch_number: U64,
    ) -> RpcResult<Vec<WrapTransaction>> {
        debug!("debug_getTransactionsByEpoch {}", epoch_number);

        let block_hashes = self
            .consensus
            .get_block_hashes_by_epoch(PrimitiveEpochNumber::Number(
                epoch_number.as_u64(),
            ))
            .map_err(|e| {
                invalid_params_rpc_err(
                    format!("Could not get block hashes by epoch: {}", e),
                    None::<bool>,
                )
            })?;

        let blocks = self
            .data_man
            .blocks_by_hash_list(&block_hashes, false)
            .ok_or_else(|| {
                invalid_params_rpc_err(
                    format!(
                        "Could not get blocks for hashes {:?}",
                        block_hashes
                    ),
                    None::<bool>,
                )
            })?;

        let pivot = blocks.last().ok_or_else(|| {
            invalid_params_rpc_err("blocks is empty", None::<bool>)
        })?;

        self.get_transactions(&blocks, pivot, epoch_number.as_u64())
    }

    fn transactions_by_block(
        &self, block_hash: H256,
    ) -> RpcResult<Vec<WrapTransaction>> {
        debug!("debug_getTransactionsByBlock {}", block_hash);

        let epoch_number =
            self.get_block_epoch_number(&block_hash).ok_or_else(|| {
                invalid_params_rpc_err(
                    format!("Could not get epoch for block {}", block_hash),
                    None::<bool>,
                )
            })?;

        let block_hashes = self
            .consensus
            .get_block_hashes_by_epoch(PrimitiveEpochNumber::Number(
                epoch_number,
            ))
            .map_err(|e| {
                invalid_params_rpc_err(
                    format!("Could not get block hashes by epoch: {}", e),
                    None::<bool>,
                )
            })?;

        let blocks = self
            .data_man
            .blocks_by_hash_list(&block_hashes, false)
            .ok_or_else(|| {
                invalid_params_rpc_err(
                    format!(
                        "Could not get blocks for hashes {:?}",
                        block_hashes
                    ),
                    None::<bool>,
                )
            })?;

        let pivot = blocks.last().ok_or_else(|| {
            invalid_params_rpc_err("blocks is empty", None::<bool>)
        })?;

        let target_blocks: Vec<Arc<Block>> = blocks
            .iter()
            .filter(|b| b.hash() == block_hash)
            .cloned()
            .collect();

        self.get_transactions(&target_blocks, pivot, epoch_number)
    }
}
