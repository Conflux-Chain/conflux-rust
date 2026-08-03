// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    ConsensusGraphStates, EpochNumber, RpcAddress, StatOnGasLoad,
    SyncGraphStates, Transaction as RpcTransaction,
};
use cfx_rpc_eth_types::WrapTransaction;
use cfx_types::{H256, U64};
// use cfxcore::verification::EpochReceiptProof;
use jsonrpsee::{core::RpcResult as JsonRpcResult, proc_macros::rpc};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use std::collections::BTreeMap;

#[rpc(server, namespace = "debug")]
pub trait DebugRpc {
    #[method(name = "inspectTxPool")]
    fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    >;

    // return all txpool transactions grouped by hex address
    #[method(name = "txPoolContent")]
    fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    >;

    // return account ready + deferred transactions
    #[method(name = "txPoolAccountTransactions")]
    fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<Vec<RpcTransaction>>;

    #[method(name = "clearTxPool")]
    fn txpool_clear(&self) -> JsonRpcResult<()>;

    #[method(name = "getNetThrottling")]
    fn net_throttling(&self) -> JsonRpcResult<throttling::Service>;

    #[method(name = "getNetNode")]
    fn net_node(
        &self, node_id: NodeId,
    ) -> JsonRpcResult<Option<(String, Node)>>;

    #[method(name = "disconnectNetNode")]
    fn net_disconnect_node(
        &self, id: NodeId, op: Option<UpdateNodeOperation>,
    ) -> JsonRpcResult<bool>;

    #[method(name = "getNetSessions")]
    fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> JsonRpcResult<Vec<SessionDetails>>;

    #[method(name = "currentSyncPhase")]
    fn current_sync_phase(&self) -> JsonRpcResult<String>;

    #[method(name = "consensusGraphState")]
    fn consensus_graph_state(&self) -> JsonRpcResult<ConsensusGraphStates>;

    #[method(name = "syncGraphState")]
    fn sync_graph_state(&self) -> JsonRpcResult<SyncGraphStates>;

    #[method(name = "statOnGasLoad")]
    fn stat_on_gas_load(
        &self, last_epoch: EpochNumber, time_window: U64,
    ) -> JsonRpcResult<Option<StatOnGasLoad>>;

    // #[method(name = "getEpochReceiptProofByTransaction")]
    // fn epoch_receipt_proof_by_transaction(
    //     &self, tx_hash: H256,
    // ) -> JsonRpcResult<Option<EpochReceiptProof>>;

    #[method(name = "getTransactionsByEpoch")]
    fn transactions_by_epoch(
        &self, epoch_number: U64,
    ) -> JsonRpcResult<Vec<WrapTransaction>>;

    #[method(name = "getTransactionsByBlock")]
    fn transactions_by_block(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Vec<WrapTransaction>>;
}
