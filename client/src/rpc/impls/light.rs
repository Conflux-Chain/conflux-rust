// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use delegate::delegate;
use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use cfx_types::{H160, H256};
use cfxcore::{light_protocol::QueryService, ConsensusGraph, PeerInfo};
use primitives::TransactionWithSignature;

use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};

use crate::rpc::{
    traits::{cfx::Cfx, debug::DebugRpc, test::TestRpc},
    types::{
        BlameInfo, Block as RpcBlock, Bytes, EpochNumber, Filter as RpcFilter,
        Log as RpcLog, Receipt as RpcReceipt, Status as RpcStatus,
        Transaction as RpcTransaction, H160 as RpcH160, H256 as RpcH256,
        U256 as RpcU256, U64 as RpcU64,
    },
};

use super::common::RpcImpl as CommonImpl;

pub struct RpcImpl {
    consensus: Arc<ConsensusGraph>,
    light: Arc<QueryService>,
}

impl RpcImpl {
    pub fn new(
        consensus: Arc<ConsensusGraph>, light: Arc<QueryService>,
    ) -> Self {
        RpcImpl { consensus, light }
    }

    fn epoch_to_height(&self, epoch: EpochNumber) -> Result<u64, String> {
        // NOTE: The epoch returned by consensus.best_state_epoch_number() is
        // not guaranteed to exist, so we use the previous one instead. This
        // way, the block `best_with_state_root + DEFERRED_STATE_EPOCH_COUNT`
        // exists and we can safely use its `deferred_state_root` field for
        // state validation.
        let best_with_state_root = self.consensus.best_state_epoch_number() - 1;

        match epoch {
            EpochNumber::Earliest => Ok(0),
            EpochNumber::LatestMined => Ok(best_with_state_root),
            EpochNumber::LatestState => Ok(best_with_state_root),
            EpochNumber::Num(num) => {
                if num > best_with_state_root {
                    return Err(format!(
                        "Epoch number too large. Received: {}. Largest: {}.",
                        num, best_with_state_root
                    ));
                }
                Ok(num)
            }
        }
    }

    fn balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let address: H160 = address.into();
        let num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getBalance address={:?} num={:?}",
            address, num
        );

        let epoch = self
            .epoch_to_height(num)
            .map_err(RpcError::invalid_params)?;

        debug!("Epoch number is {}", epoch);

        let balance = self
            .light
            .get_account(epoch, address)
            .map(|account| account.balance.into())
            .unwrap_or_default();

        Ok(balance)
    }

    #[allow(unused_variables)]
    fn call(
        &self, rpc_tx: RpcTransaction, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        // TODO
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn estimate_gas(&self, rpc_tx: RpcTransaction) -> RpcResult<RpcU256> {
        // TODO
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>> {
        // TODO
        unimplemented!()
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        let raw: Vec<u8> = raw.into_vec();

        // decode tx so that we have its hash
        // this way we also avoid spamming peers with invalid txs
        let tx: TransactionWithSignature = rlp::decode(&raw.clone())
            .map_err(|e| format!("Failed to decode tx: {:?}", e))
            .map_err(RpcError::invalid_params)?;

        debug!("Deserialized tx: {:?}", tx);

        // TODO(thegaram): consider adding a light node specific tx pool;
        // light nodes would track those txs and maintain their statuses
        // for future queries

        match /* success = */ self.light.send_raw_tx(raw) {
            true => Ok(tx.hash().into()),
            false => Err(RpcError::invalid_params("Unable to relay tx")),
        }
    }

    #[allow(unused_variables)]
    fn send_usable_genesis_accounts(
        &self, raw_addresses: Bytes, raw_secrets: Bytes,
    ) -> RpcResult<Bytes> {
        // TODO
        unimplemented!()
    }

    pub fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> RpcResult<Option<RpcTransaction>> {
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        // TODO(thegaram): try to retrieve from local tx pool or cache first

        let maybe_tx = self.light.get_tx(hash.into());
        Ok(maybe_tx.map(|tx| RpcTransaction::from_signed(&tx, None)))
    }
}

// macro for reducing boilerplate for unsupported methods
macro_rules! not_supported {
    () => {};
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> $ret:ty )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> $ret )? {
            Err(RpcError::method_not_found())
        }

        not_supported!($($tail)*);
    };
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
            fn balance(&self, address: RpcH160, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn call(&self, rpc_tx: RpcTransaction, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn estimate_gas(&self, rpc_tx: RpcTransaction) -> RpcResult<RpcU256>;
            fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256>;
            fn send_usable_genesis_accounts(& self,raw_addresses:Bytes, raw_secrets:Bytes) ->RpcResult<Bytes>;
            fn transaction_by_hash(&self, hash: RpcH256) -> RpcResult<Option<RpcTransaction>>;
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
            fn get_best_block_hash(&self) -> RpcResult<H256>;
            fn get_block_count(&self) -> RpcResult<u64>;
            fn get_goodput(&self) -> RpcResult<isize>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn get_transaction_receipt(&self, tx_hash: H256) -> RpcResult<Option<RpcReceipt>>;
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
        }
    }

    not_supported! {
        fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, tx_data_len: Option<usize>) -> RpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
        fn generate_one_block_special(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<()>;
        fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
        fn generate(&self, num_blocks: usize, num_txs: usize) -> RpcResult<Vec<H256>>;
    }
}

#[allow(dead_code)]
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
            fn net_high_priority_packets(&self) -> RpcResult<usize>;
            fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> RpcResult<Option<usize>>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> RpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> RpcResult<throttling::Service>;
            fn tx_inspect(&self, hash: RpcH256) -> RpcResult<BTreeMap<String, String>>;
            fn txpool_content(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;
        }
    }

    not_supported! {
        fn current_sync_phase(&self) -> RpcResult<String>;
    }
}
