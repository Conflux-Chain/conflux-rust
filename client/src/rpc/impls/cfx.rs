// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use delegate::delegate;

use crate::rpc::{
    traits::{cfx::Cfx, debug::DebugRpc, test::TestRpc},
    types::{
        BlameInfo, Block as RpcBlock, Bytes, ConsensusGraphStates, EpochNumber,
        Filter as RpcFilter, Log as RpcLog, Receipt as RpcReceipt,
        Status as RpcStatus, Transaction as RpcTransaction, H160 as RpcH160,
        H256 as RpcH256, U256 as RpcU256, U64 as RpcU64,
    },
};
use blockgen::BlockGenerator;
use cfx_types::{H160, H256};
use cfxcore::{
    block_parameters::MAX_BLOCK_SIZE_IN_BYTES, state_exposer::STATE_EXPOSER,
    PeerInfo, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use primitives::{
    Action, SignedTransaction, Transaction, TransactionWithSignature,
};
use rlp::Rlp;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use super::common::RpcImpl as CommonImpl;

pub struct RpcImpl {
    pub consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    block_gen: Arc<BlockGenerator>,
    tx_pool: SharedTransactionPool,
    tx_gen: Arc<TransactionGenerator>,
}
use txgen::TransactionGenerator;

impl RpcImpl {
    pub fn new(
        consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        block_gen: Arc<BlockGenerator>, tx_pool: SharedTransactionPool,
        tx_gen: Arc<TransactionGenerator>,
    ) -> Self
    {
        RpcImpl {
            consensus,
            sync,
            block_gen,
            tx_pool,
            tx_gen,
        }
    }

    fn code(
        &self, addr: RpcH160, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch_number = epoch_number.unwrap_or(EpochNumber::LatestState);
        let address: H160 = addr.into();
        info!(
            "RPC Request: cfx_getCode address={:?} epoch_num={:?}",
            address, epoch_number
        );

        self.consensus
            .get_code(address, epoch_number.into())
            .map(Bytes::new)
            .map_err(|err| RpcError::invalid_params(err))
    }

    fn balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            address, num
        );

        self.consensus
            .get_balance(address, num.into())
            .map(|x| x.into())
            .map_err(|err| RpcError::invalid_params(err))
    }

    //    fn account(
    //        &self, address: RpcH160, include_txs: bool, num_txs: RpcU64,
    //        epoch_num: Option<EpochNumber>,
    //    ) -> RpcResult<Account>
    //    {
    //        let inner = &mut *self.consensus.inner.write();
    //
    //        let address: H160 = address.into();
    //        let num_txs = num_txs.as_usize();
    //        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);
    //        info!(
    //            "RPC Request: cfx_getAccount address={:?} include_txs={:?}
    // num_txs={:?} epoch_num={:?}",            address, include_txs,
    // num_txs, epoch_num        );
    //        self.consensus
    //            .get_account(
    //                address,
    //                num_txs,
    //                epoch_num.into(),
    //            )
    //            .and_then(|(balance, transactions)| {
    //                Ok(Account {
    //                    balance: balance.into(),
    //                    transactions: BlockTransactions::new(
    //                        &transactions,
    //                        include_txs,
    //                        inner,
    //                    ),
    //                })
    //            })
    //            .map_err(|err| RpcError::invalid_params(err))
    //    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Rlp::new(&raw.into_vec())
            .as_val()
            .map_err(|err| {
                RpcError::invalid_params(format!("Error: {:?}", err))
            })
            .and_then(|tx| {
                let (signed_trans, failed_trans) = self.tx_pool.insert_new_transactions(
                    vec![tx],
                );
                if signed_trans.len() + failed_trans.len() > 1 {
                    // This should never happen
                    error!("insert_new_transactions failed, invalid length of returned result vector {}", signed_trans.len() + failed_trans.len());
                    Ok(H256::zero().into())
                } else if signed_trans.len() + failed_trans.len() == 0 {
                    // For tx in transactions_pubkey_cache, we simply ignore them
                    debug!("insert_new_transactions ignores inserted transactions");
                    Err(RpcError::invalid_params(String::from("tx already exist")))
                } else {
                    if signed_trans.is_empty() {
                        let mut tx_err = String::from("");
                        for (_, e) in failed_trans.iter() {
                            tx_err = e.clone();
                            break;
                        }
                        Err(RpcError::invalid_params(tx_err))
                    } else {
                        let tx_hash = signed_trans[0].hash();
                        self.sync.append_received_transactions(signed_trans);
                        Ok(tx_hash.into())
                    }
                }
            })
    }

    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes> {
        info!(
            "RPC Request: send_usable_genesis_accounts start from {:?}",
            account_start_index
        );
        self.tx_gen
            .set_genesis_accounts_start_index(account_start_index);
        Ok(Bytes::new("1".into()))
    }

    pub fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> RpcResult<Option<RpcTransaction>> {
        let hash: H256 = hash.into();
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        if let Some((transaction, receipt, tx_address)) =
            self.consensus.get_transaction_info_by_hash(&hash)
        {
            Ok(Some(RpcTransaction::from_signed(
                &transaction,
                Some(RpcReceipt::new(transaction.clone(), receipt, tx_address)),
            )))
        } else {
            if let Some(transaction) = self.tx_pool.get_transaction(&hash) {
                return Ok(Some(RpcTransaction::from_signed(
                    &transaction,
                    None,
                )));
            }

            Ok(None)
        }
    }

    fn transaction_receipt(
        &self, tx_hash: RpcH256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt({:?})", hash);
        let transaction_info =
            self.consensus.get_transaction_info_by_hash(&hash);
        let (tx, receipt, address) = match transaction_info {
            None => return Ok(None),
            Some(info) => info,
        };
        let hash = address.block_hash.into();
        let mut receipt = RpcReceipt::new(tx, receipt, address);
        let epoch_number = self.consensus.get_block_epoch_number(&hash);
        receipt.set_epoch_number(epoch_number);
        if let Some(pivot_height) = epoch_number {
            if let Some(state_root) =
                self.consensus.get_state_root_by_pivot_height(pivot_height)
            {
                receipt.set_state_root(RpcH256::from(state_root));
            }
        }
        Ok(Some(receipt))
    }

    fn generate(
        &self, num_blocks: usize, num_txs: usize,
    ) -> RpcResult<Vec<H256>> {
        info!("RPC Request: generate({:?})", num_blocks);
        let mut hashes = Vec::new();
        for _i in 0..num_blocks {
            hashes.push(self.block_gen.generate_block_with_transactions(
                num_txs,
                MAX_BLOCK_SIZE_IN_BYTES,
            ));
        }
        Ok(hashes)
    }

    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>,
    ) -> RpcResult<H256>
    {
        info!(
            "RPC Request: generate_fixed_block({:?}, {:?}, {:?}, {:?})",
            parent_hash, referee, num_txs, difficulty
        );
        match self.block_gen.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty.unwrap_or(0),
            adaptive,
        ) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_one_block()");
        let hash =
            self.block_gen
                .generate_block(num_txs, block_size_limit, vec![]);
        Ok(hash)
    }

    fn generate_one_block_special(
        &self, num_txs: usize, mut block_size_limit: usize,
        num_txs_simple: usize, num_txs_erc20: usize,
    ) -> RpcResult<()>
    {
        info!("RPC Request: generate_one_block_special()");

        let block_gen = &self.block_gen;
        let special_transactions = block_gen.generate_special_transactions(
            &mut block_size_limit,
            num_txs_simple,
            num_txs_erc20,
        );

        block_gen.generate_block(
            num_txs,
            block_size_limit,
            special_transactions,
        );

        Ok(())
    }

    fn generate_custom_block(
        &self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes,
        adaptive: Option<bool>,
    ) -> RpcResult<H256>
    {
        info!("RPC Request: generate_custom_block()");

        let transactions = self.decode_raw_txs(raw_txs, 0)?;

        match self.block_gen.generate_custom_block_with_parent(
            parent_hash,
            referee,
            transactions,
            adaptive.unwrap_or(false),
        ) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn decode_raw_txs(
        &self, raw_txs: Bytes, tx_data_len: usize,
    ) -> RpcResult<Vec<Arc<SignedTransaction>>> {
        let txs: Vec<TransactionWithSignature> =
            Rlp::new(&raw_txs.into_vec()).as_list().map_err(|err| {
                RpcError::invalid_params(format!("Decode error: {:?}", err))
            })?;

        let mut transactions = Vec::new();

        for tx in txs {
            match tx.recover_public() {
                Ok(public) => {
                    let mut signed_tx = SignedTransaction::new(public, tx);
                    if tx_data_len > 0 {
                        signed_tx.transaction.unsigned.data =
                            vec![0; tx_data_len];
                    }
                    transactions.push(Arc::new(signed_tx));
                }
                Err(e) => {
                    return Err(RpcError::invalid_params(format!(
                        "Recover public error: {:?}",
                        e
                    )));
                }
            }
        }

        Ok(transactions)
    }

    fn generate_block_with_fake_txs(
        &self, raw_txs_without_data: Bytes, tx_data_len: Option<usize>,
    ) -> RpcResult<H256> {
        let transactions = self
            .decode_raw_txs(raw_txs_without_data, tx_data_len.unwrap_or(0))?;
        Ok(self.block_gen.generate_custom_block(transactions))
    }

    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256> {
        Ok(self.block_gen.generate_block_with_blame_info(
            num_txs,
            block_size_limit,
            vec![],
            blame_info.blame,
            blame_info.deferred_state_root.and_then(|x| Some(x.into())),
            blame_info
                .deferred_receipts_root
                .and_then(|x| Some(x.into())),
            blame_info
                .deferred_logs_bloom_hash
                .and_then(|x| Some(x.into())),
        ))
    }

    fn call(
        &self, rpc_tx: RpcTransaction, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);

        let tx = Transaction {
            nonce: rpc_tx.nonce.into(),
            gas: rpc_tx.gas.into(),
            gas_price: rpc_tx.gas_price.into(),
            value: rpc_tx.value.into(),
            action: match rpc_tx.to {
                Some(to) => Action::Call(to.into()),
                None => Action::Create,
            },
            data: rpc_tx.data.into(),
        };
        debug!("RPC Request: cfx_call");
        let mut signed_tx = SignedTransaction::new_unsigned(
            TransactionWithSignature::new_unsigned(tx),
        );
        signed_tx.sender = rpc_tx.from.into();
        trace!("call tx {:?}", signed_tx);
        self.consensus
            .call_virtual(&signed_tx, epoch.into())
            .map(|output| Bytes::new(output.0))
            .map_err(|e| RpcError::invalid_params(e))
    }

    fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>> {
        info!("RPC Request: cfx_getLogs({:?})", filter);
        self.consensus
            .logs(filter.into())
            .map_err(|e| format!("{}", e))
            .map_err(RpcError::invalid_params)
            .map(|logs| logs.iter().cloned().map(RpcLog::from).collect())
    }

    fn estimate_gas(&self, rpc_tx: RpcTransaction) -> RpcResult<RpcU256> {
        let tx = Transaction {
            nonce: rpc_tx.nonce.into(),
            gas: rpc_tx.gas.into(),
            gas_price: rpc_tx.gas_price.into(),
            value: rpc_tx.value.into(),
            action: match rpc_tx.to {
                Some(to) => Action::Call(to.into()),
                None => Action::Create,
            },
            data: rpc_tx.data.into(),
        };
        let mut signed_tx = SignedTransaction::new_unsigned(
            TransactionWithSignature::new_unsigned(tx),
        );
        signed_tx.sender = rpc_tx.from.into();
        trace!("call tx {:?}", signed_tx);
        let result = self.consensus.estimate_gas(&signed_tx);
        result
            .map_err(|e| {
                warn!("Transaction execution error {:?}", e);
                RpcError::internal_error()
            })
            .map(|x| x.into())
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        Ok(self.sync.current_sync_phase().name().into())
    }

    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()> {
        self.sync.expire_block_gc(timeout);
        Ok(())
    }

    pub fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates> {
        let consensus_graph_states =
            STATE_EXPOSER.consensus_graph.lock().retrieve();
        Ok(ConsensusGraphStates::new(consensus_graph_states))
    }
}

#[allow(dead_code)]
pub struct CfxHandler {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl CfxHandler {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        CfxHandler { common, rpc_impl }
    }
}

impl Cfx for CfxHandler {
    delegate! {
        target self.common {
            fn best_block_hash(&self) -> RpcResult<RpcH256>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> RpcResult<RpcBlock>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64) -> RpcResult<RpcBlock>;
            fn block_by_hash(&self, hash: RpcH256, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn gas_price(&self) -> RpcResult<RpcU256>;
            fn transaction_count(&self, address: RpcH160, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
        }

        target self.rpc_impl {
            fn code(&self, addr: RpcH160, epoch_number: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn balance(&self, address: RpcH160, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn call(&self, rpc_tx: RpcTransaction, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn estimate_gas(&self, rpc_tx: RpcTransaction) -> RpcResult<RpcU256>;
            fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256>;
            fn transaction_by_hash(&self, hash: RpcH256) -> RpcResult<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: RpcH256) -> RpcResult<Option<RpcReceipt>>;
        }
    }
}

#[allow(dead_code)]
pub struct TestRpcImpl {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl TestRpcImpl {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        TestRpcImpl { common, rpc_impl }
    }
}

impl TestRpc for TestRpcImpl {
    delegate! {
        target self.common {
            fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;
            fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn chain(&self) -> RpcResult<Vec<RpcBlock>>;
            fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn get_block_count(&self) -> RpcResult<u64>;
            fn get_goodput(&self) -> RpcResult<String>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn get_transaction_receipt(&self, tx_hash: H256) -> RpcResult<Option<RpcReceipt>>;
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
        }

        target self.rpc_impl {
            fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
            fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
            fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, tx_data_len: Option<usize>) -> RpcResult<H256>;
            fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
            fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
            fn generate_one_block_special(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<()>;
            fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
            fn generate(&self, num_blocks: usize, num_txs: usize) -> RpcResult<Vec<H256>>;
            fn send_usable_genesis_accounts(& self, account_start_index: usize) -> RpcResult<Bytes>;
        }
    }
}

pub struct DebugRpcImpl {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl DebugRpcImpl {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        DebugRpcImpl { common, rpc_impl }
    }
}

impl DebugRpc for DebugRpcImpl {
    delegate! {
        target self.common {
            fn clear_tx_pool(&self) -> RpcResult<()>;
            fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> RpcResult<Option<usize>>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> RpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> RpcResult<throttling::Service>;
            fn tx_inspect(&self, hash: RpcH256) -> RpcResult<BTreeMap<String, String>>;
            fn txpool_content(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;
        }

        target self.rpc_impl {
            fn current_sync_phase(&self) -> RpcResult<String>;
            fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
        }
    }
}
