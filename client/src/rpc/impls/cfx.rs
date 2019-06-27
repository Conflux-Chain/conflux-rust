// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    traits::cfx::{Cfx, DebugRpc, TestRpc},
    types::{
        Block as RpcBlock, Bytes, EpochNumber, Receipt as RpcReceipt, Receipt,
        Status as RpcStatus, Transaction as RpcTransaction, H160 as RpcH160,
        H256 as RpcH256, U256 as RpcU256, U64 as RpcU64,
    },
};
use blockgen::BlockGenerator;
use cfx_types::{H160, H256};
use cfxcore::{
    storage::StorageManager, PeerInfo, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use jsonrpc_macros::Trailing;
use network::{
    get_high_priority_packets,
    node_table::{Node, NodeEndpoint, NodeEntry, NodeId},
    throttling::{self, THROTTLING_SERVICE},
    SessionDetails,
};
use parking_lot::{Condvar, Mutex};
use primitives::{
    block::MAX_BLOCK_SIZE_IN_BYTES, Action,
    EpochNumber as PrimitiveEpochNumber, SignedTransaction, Transaction,
    TransactionWithSignature,
};
use rlp::Rlp;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

pub struct RpcImpl {
    pub consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    #[allow(dead_code)]
    storage_manager: Arc<StorageManager>,
    block_gen: Arc<BlockGenerator>,
    tx_pool: SharedTransactionPool,
    exit: Arc<(Mutex<bool>, Condvar)>,
}

impl RpcImpl {
    pub fn new(
        consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        storage_manager: Arc<StorageManager>, block_gen: Arc<BlockGenerator>,
        tx_pool: SharedTransactionPool, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Self
    {
        RpcImpl {
            consensus,
            sync,
            storage_manager,
            block_gen,
            tx_pool,
            exit,
        }
    }

    fn get_primitive_epoch_number(
        &self, number: EpochNumber,
    ) -> PrimitiveEpochNumber {
        match number {
            EpochNumber::Earliest => PrimitiveEpochNumber::Earliest,
            EpochNumber::LatestMined => PrimitiveEpochNumber::LatestMined,
            EpochNumber::LatestState => PrimitiveEpochNumber::LatestState,
            EpochNumber::Num(num) => PrimitiveEpochNumber::Number(num.into()),
        }
    }

    fn best_block_hash(&self) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_getBestBlockHash()");
        Ok(self.consensus.best_block_hash().into())
    }

    fn gas_price(&self) -> RpcResult<RpcU256> {
        info!("RPC Request: cfx_gasPrice()");
        Ok(self.consensus.gas_price().unwrap_or(0.into()).into())
    }

    fn epoch_number(
        &self, epoch_num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber({:?})", epoch_num);
        match self.consensus.get_height_from_epoch_number(
            self.get_primitive_epoch_number(epoch_num),
        ) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn block_by_epoch_number(
        &self, epoch_num: EpochNumber, include_txs: bool,
    ) -> RpcResult<RpcBlock> {
        let inner = &mut *self.consensus.inner.write();
        info!("RPC Request: cfx_getBlockByEpochNumber epoch_number={:?} include_txs={:?}", epoch_num, include_txs);
        inner
            .get_hash_from_epoch_number(
                self.get_primitive_epoch_number(epoch_num),
            )
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|hash| {
                let block = self
                    .consensus
                    .data_man
                    .block_by_hash(&hash, false)
                    .unwrap();
                Ok(RpcBlock::new(&*block, inner, include_txs))
            })
    }

    fn block_by_hash(
        &self, hash: RpcH256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let hash: H256 = hash.into();
        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );
        let inner = &mut *self.consensus.inner.write();

        if let Some(block) = self.consensus.data_man.block_by_hash(&hash, false)
        {
            let result_block = Some(RpcBlock::new(&*block, inner, include_txs));
            Ok(result_block)
        } else {
            Ok(None)
        }
    }

    fn block_by_hash_with_pivot_assumption(
        &self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64,
    ) -> RpcResult<RpcBlock> {
        let inner = &mut *self.consensus.inner.write();

        let block_hash: H256 = block_hash.into();
        let pivot_hash: H256 = pivot_hash.into();
        let epoch_number: usize = epoch_number.as_usize();
        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        inner
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|_| {
                if let Some(block) =
                    self.consensus.data_man.block_by_hash(&block_hash, false)
                {
                    debug!("Build RpcBlock {}", block.hash());
                    let result_block = RpcBlock::new(&*block, inner, true);
                    Ok(result_block)
                } else {
                    Err(RpcError::invalid_params(
                        "Error: can not find expected block".to_owned(),
                    ))
                }
            })
    }

    fn chain(&self) -> RpcResult<Vec<RpcBlock>> {
        info!("RPC Request: cfx_getChain");
        let inner = &mut *self.consensus.inner.write();
        Ok(inner
            .all_blocks_with_topo_order()
            .iter()
            .map(|x| {
                RpcBlock::new(
                    self.consensus
                        .data_man
                        .block_by_hash(x, false)
                        .expect("Error to get block by hash")
                        .as_ref(),
                    inner,
                    true,
                )
            })
            .collect())
    }

    fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> RpcResult<Option<RpcTransaction>> {
        let hash: H256 = hash.into();
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        if let Some((transaction, receipt, tx_address)) =
            self.consensus.get_transaction_info_by_hash(&hash)
        {
            Ok(Some(RpcTransaction::from_signed(
                &transaction,
                Some(Receipt::new(transaction.clone(), receipt, tx_address)),
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

    fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>> {
        info!("RPC Request: cfx_getBlocks epoch_number={:?}", num);

        self.consensus
            .inner
            .read_recursive()
            .block_hashes_by_epoch(self.get_primitive_epoch_number(num))
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    fn balance(
        &self, address: RpcH160, num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            address, num
        );

        self.consensus
            .get_balance(address, self.get_primitive_epoch_number(num))
            .map(|x| x.into())
            .map_err(|err| RpcError::invalid_params(err))
    }

    //    fn account(
    //        &self, address: RpcH160, include_txs: bool, num_txs: RpcU64,
    //        epoch_num: Trailing<EpochNumber>,
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
    //                self.get_primitive_epoch_number(epoch_num),
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

    fn transaction_count(
        &self, address: RpcH160, num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        info!(
            "RPC Request: cfx_getTransactionCount address={:?} epoch_num={:?}",
            address, num
        );

        self.consensus
            .transaction_count(
                address.into(),
                self.get_primitive_epoch_number(num),
            )
            .map_err(|err| RpcError::invalid_params(err))
            .map(|x| x.into())
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Rlp::new(&raw.into_vec())
            .as_val()
            .map_err(|err| {
                RpcError::invalid_params(format!("Error: {:?}", err))
            })
            .and_then(|tx| {
                let (signed_trans, failed_trans) = self.tx_pool.insert_new_transactions(
                    self.consensus.best_state_block_hash(),
                    &vec![tx],
                );
                if signed_trans.len() + failed_trans.len() != 1 {
                    error!("insert_new_transactions failed, invalid length of returned result vector {}", signed_trans.len() + failed_trans.len());
                    Ok(H256::new().into())
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

    fn say_hello(&self) -> RpcResult<String> { Ok("Hello, world".into()) }

    fn get_best_block_hash(&self) -> RpcResult<H256> {
        info!("RPC Request: get_best_block_hash()");
        Ok(self.consensus.best_block_hash())
    }

    fn get_block_count(&self) -> RpcResult<usize> {
        info!("RPC Request: get_block_count()");
        Ok(self.consensus.block_count())
    }

    fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()> {
        let node = NodeEntry {
            id: node_id,
            endpoint: NodeEndpoint {
                address,
                udp_port: address.port(),
            },
        };
        info!("RPC Request: add_peer({:?})", node.clone());
        match self.sync.add_peer(node) {
            Ok(x) => Ok(x),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()> {
        let node = NodeEntry {
            id: node_id,
            endpoint: NodeEndpoint {
                address,
                udp_port: address.port(),
            },
        };
        info!("RPC Request: drop_peer({:?})", node.clone());
        match self.sync.drop_peer(node) {
            Ok(_) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
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
        difficulty: u64, adaptive: bool,
    ) -> RpcResult<H256>
    {
        info!(
            "RPC Request: generate_fixed_block({:?}, {:?}, {:?}, {:?})",
            parent_hash, referee, num_txs, difficulty
        );
        let hash = self.block_gen.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty,
            adaptive,
        );
        Ok(hash)
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
        adaptive: bool,
    ) -> RpcResult<H256>
    {
        info!("RPC Request: generate_custom_block()");

        let transactions = self.decode_raw_txs(raw_txs, 0)?;

        let hash = self.block_gen.generate_custom_block_with_parent(
            parent_hash,
            referee,
            transactions,
            adaptive,
        );

        Ok(hash)
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
        &self, raw_txs_without_data: Bytes, tx_data_len: Trailing<usize>,
    ) -> RpcResult<H256> {
        let transactions = self
            .decode_raw_txs(raw_txs_without_data, tx_data_len.unwrap_or(0))?;
        Ok(self.block_gen.generate_custom_block(transactions))
    }

    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        info!("RPC Request: get_peer_info");
        Ok(self.sync.get_peer_info())
    }

    fn stop(&self) -> RpcResult<()> {
        *self.exit.0.lock() = true;
        self.exit.1.notify_all();

        Ok(())
    }

    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        match self.sync.sign_challenge(challenge) {
            Ok(r) => Ok(r),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    fn get_status(&self) -> RpcResult<RpcStatus> {
        let best_hash = self.consensus.best_block_hash();
        let block_number = self.consensus.block_count();
        let tx_count = self.tx_pool.len();
        if let Some(epoch_number) =
            self.consensus.get_block_epoch_number(&best_hash)
        {
            Ok(RpcStatus {
                best_hash: RpcH256::from(best_hash),
                epoch_number,
                block_number,
                pending_tx_number: tx_count,
            })
        } else {
            Err(RpcError::internal_error())
        }
    }

    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        match self.sync.add_latency(id, latency_ms) {
            Ok(_) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    /// The first element is true if the tx is executed in a confirmed block.
    /// The second element indicate the execution result (standin
    /// for receipt)
    fn get_transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let maybe_receipt =
            self.consensus.get_transaction_info_by_hash(&tx_hash).map(
                |(tx, receipt, address)| RpcReceipt::new(tx, receipt, address),
            );
        Ok(maybe_receipt)
    }

    fn call(
        &self, rpc_tx: RpcTransaction, epoch: Trailing<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);
        let epoch = self.get_primitive_epoch_number(epoch);

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
            .call_virtual(&signed_tx, epoch)
            .map(|output| Bytes::new(output.0))
            .map_err(|e| RpcError::invalid_params(e))
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

    fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>> {
        let (ready_len, deferred_len) = self.tx_pool.stats();

        let mut ret: BTreeMap<String, usize> = BTreeMap::new();
        ret.insert("ready".into(), ready_len);
        ret.insert("deferred".into(), deferred_len);

        Ok(ret)
    }

    fn txpool_inspect(
        &self,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content();
        let converter = |tx: Arc<SignedTransaction>| -> String {
            let to = match tx.action {
                Action::Create => "<Create contract>".into(),
                Action::Call(addr) => format!("{:?}", addr),
            };

            format!(
                "{}: {:?} wei + {:?} gas * {:?} wei",
                to, tx.value, tx.gas, tx.gas_price
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
        &self,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content();
        let converter = |tx: Arc<SignedTransaction>| -> RpcTransaction {
            RpcTransaction::from_signed(&tx, None)
        };

        let mut ret: BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        > = BTreeMap::new();
        ret.insert("ready".into(), grouped_txs(ready_txs, converter));
        ret.insert("deferred".into(), grouped_txs(deferred_txs, converter));

        Ok(ret)
    }

    fn clear_tx_pool(&self) -> RpcResult<()> {
        self.tx_pool.clear_tx_pool();
        Ok(())
    }

    fn net_throttling(&self) -> RpcResult<throttling::Service> {
        Ok(THROTTLING_SERVICE.read().clone())
    }

    fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>> {
        match self.sync.get_network_service().get_node(&id) {
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

    fn net_sessions(
        &self, node_id: Trailing<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>> {
        match self
            .sync
            .get_network_service()
            .get_detailed_sessions(node_id.into())
        {
            None => Ok(Vec::new()),
            Some(sessions) => Ok(sessions),
        }
    }

    fn net_high_priority_packets(&self) -> RpcResult<usize> {
        Ok(get_high_priority_packets())
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
        let addr_entry: &mut BTreeMap<usize, Vec<T>> =
            addr_grouped_txs.entry(addr).or_insert(BTreeMap::new());

        let nonce = tx.nonce().as_usize();
        let nonce_entry: &mut Vec<T> =
            addr_entry.entry(nonce).or_insert(Vec::new());

        nonce_entry.push(converter(tx));
    }

    addr_grouped_txs
}

pub struct CfxHandler {
    rpc_impl: Arc<RpcImpl>,
}

impl CfxHandler {
    pub fn new(rpc_impl: Arc<RpcImpl>) -> Self { CfxHandler { rpc_impl } }
}

impl Cfx for CfxHandler {
    fn best_block_hash(&self) -> RpcResult<RpcH256> {
        self.rpc_impl.best_block_hash()
    }

    fn estimate_gas(&self, rpc_tx: RpcTransaction) -> RpcResult<RpcU256> {
        self.rpc_impl.estimate_gas(rpc_tx)
    }

    fn gas_price(&self) -> RpcResult<RpcU256> { self.rpc_impl.gas_price() }

    fn epoch_number(
        &self, epoch_num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        self.rpc_impl.epoch_number(epoch_num)
    }

    fn block_by_epoch_number(
        &self, epoch_num: EpochNumber, include_txs: bool,
    ) -> RpcResult<RpcBlock> {
        self.rpc_impl.block_by_epoch_number(epoch_num, include_txs)
    }

    fn block_by_hash(
        &self, hash: RpcH256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        self.rpc_impl.block_by_hash(hash, include_txs)
    }

    fn block_by_hash_with_pivot_assumption(
        &self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64,
    ) -> RpcResult<RpcBlock> {
        self.rpc_impl.block_by_hash_with_pivot_assumption(
            block_hash,
            pivot_hash,
            epoch_number,
        )
    }

    fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> RpcResult<Option<RpcTransaction>> {
        self.rpc_impl.transaction_by_hash(hash)
    }

    fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>> {
        self.rpc_impl.blocks_by_epoch(num)
    }

    fn balance(
        &self, address: RpcH160, num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        self.rpc_impl.balance(address, num)
    }

    //    fn account(
    //        &self, address: RpcH160, include_txs: bool, num_txs: RpcU64,
    //        epoch_num: Trailing<EpochNumber>,
    //    ) -> RpcResult<Account>
    //    {
    //        self.rpc_impl
    //            .account(address, include_txs, num_txs, epoch_num)
    //    }

    fn transaction_count(
        &self, address: RpcH160, num: Trailing<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        self.rpc_impl.transaction_count(address, num)
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        self.rpc_impl.send_raw_transaction(raw)
    }

    fn call(
        &self, rpc_tx: RpcTransaction, epoch: Trailing<EpochNumber>,
    ) -> RpcResult<Bytes> {
        self.rpc_impl.call(rpc_tx, epoch)
    }
}

pub struct TestRpcImpl {
    rpc_impl: Arc<RpcImpl>,
}

impl TestRpcImpl {
    pub fn new(rpc_impl: Arc<RpcImpl>) -> Self { TestRpcImpl { rpc_impl } }
}

impl TestRpc for TestRpcImpl {
    fn say_hello(&self) -> RpcResult<String> { self.rpc_impl.say_hello() }

    fn get_best_block_hash(&self) -> RpcResult<H256> {
        self.rpc_impl.get_best_block_hash()
    }

    fn get_block_count(&self) -> RpcResult<usize> {
        self.rpc_impl.get_block_count()
    }

    fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()> {
        self.rpc_impl.add_peer(node_id, address)
    }

    fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()> {
        self.rpc_impl.drop_peer(node_id, address)
    }

    fn chain(&self) -> RpcResult<Vec<RpcBlock>> { self.rpc_impl.chain() }

    fn generate(
        &self, num_blocks: usize, num_txs: usize,
    ) -> RpcResult<Vec<H256>> {
        self.rpc_impl.generate(num_blocks, num_txs)
    }

    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Trailing<u64>,
    ) -> RpcResult<H256>
    {
        self.rpc_impl.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty.unwrap_or(0),
            adaptive,
        )
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        self.rpc_impl.generate_one_block(num_txs, block_size_limit)
    }

    fn generate_one_block_special(
        &self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize,
        num_txs_erc20: usize,
    ) -> RpcResult<()>
    {
        self.rpc_impl.generate_one_block_special(
            num_txs,
            block_size_limit,
            num_txs_simple,
            num_txs_erc20,
        )
    }

    fn generate_custom_block(
        &self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes,
        adaptive: Trailing<bool>,
    ) -> RpcResult<H256>
    {
        self.rpc_impl.generate_custom_block(
            parent_hash,
            referee,
            raw_txs,
            adaptive.unwrap_or(false),
        )
    }

    fn generate_block_with_fake_txs(
        &self, raw_txs_without_data: Bytes, tx_data_len: Trailing<usize>,
    ) -> RpcResult<H256> {
        self.rpc_impl
            .generate_block_with_fake_txs(raw_txs_without_data, tx_data_len)
    }

    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        self.rpc_impl.get_peer_info()
    }

    fn stop(&self) -> RpcResult<()> { self.rpc_impl.stop() }

    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        self.rpc_impl.get_nodeid(challenge)
    }

    fn get_status(&self) -> RpcResult<RpcStatus> { self.rpc_impl.get_status() }

    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        self.rpc_impl.add_latency(id, latency_ms)
    }

    /// The first element is true if the tx is executed in a confirmed block.
    /// The second element indicate the execution result (standin
    /// for receipt)
    fn get_transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        self.rpc_impl.get_transaction_receipt(tx_hash)
    }
}

pub struct DebugRpcImpl {
    rpc_impl: Arc<RpcImpl>,
}

impl DebugRpcImpl {
    pub fn new(rpc_impl: Arc<RpcImpl>) -> Self { DebugRpcImpl { rpc_impl } }
}

impl DebugRpc for DebugRpcImpl {
    fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>> {
        self.rpc_impl.txpool_status()
    }

    fn txpool_inspect(
        &self,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        self.rpc_impl.txpool_inspect()
    }

    fn txpool_content(
        &self,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        self.rpc_impl.txpool_content()
    }

    fn clear_tx_pool(&self) -> RpcResult<()> { self.rpc_impl.clear_tx_pool() }

    fn net_throttling(&self) -> RpcResult<throttling::Service> {
        self.rpc_impl.net_throttling()
    }

    fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>> {
        self.rpc_impl.net_node(id)
    }

    fn net_sessions(
        &self, node_id: Trailing<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>> {
        self.rpc_impl.net_sessions(node_id)
    }

    fn net_high_priority_packets(&self) -> RpcResult<usize> {
        self.rpc_impl.net_high_priority_packets()
    }
}
