// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{
    BlockHashOrEpochNumber, Bytes as RpcBytes, ConsensusGraphStates,
    Receipt as RpcReceipt, RpcAddress, SyncGraphStates,
    Transaction as RpcTransaction,
};
use crate::rpc::types::SendTxRequest;
use cfx_types::{H256, H520, U128};
use jsonrpc_core::{BoxFuture, Result as JsonRpcResult};
use jsonrpc_derive::rpc;
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use std::collections::BTreeMap;

#[rpc(server)]
pub trait LocalRpc {
    #[rpc(name = "txpool_inspect")]
    fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    >;

    // return all txpool transactions grouped by hex address
    #[rpc(name = "txpool_content")]
    fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    >;

    // return account ready + deferred transactions
    #[rpc(name = "txpool_accountTransactions")]
    fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<Vec<RpcTransaction>>;

    #[rpc(name = "txpool_clear")]
    fn txpool_clear(&self) -> JsonRpcResult<()>;

    #[rpc(name = "net_throttling")]
    fn net_throttling(&self) -> JsonRpcResult<throttling::Service>;

    #[rpc(name = "net_node")]
    fn net_node(
        &self, node_id: NodeId,
    ) -> JsonRpcResult<Option<(String, Node)>>;

    #[rpc(name = "net_disconnect_node")]
    fn net_disconnect_node(
        &self, id: NodeId, op: Option<UpdateNodeOperation>,
    ) -> JsonRpcResult<bool>;

    #[rpc(name = "net_sessions")]
    fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> JsonRpcResult<Vec<SessionDetails>>;

    #[rpc(name = "current_sync_phase")]
    fn current_sync_phase(&self) -> JsonRpcResult<String>;

    #[rpc(name = "consensus_graph_state")]
    fn consensus_graph_state(&self) -> JsonRpcResult<ConsensusGraphStates>;

    #[rpc(name = "sync_graph_state")]
    fn sync_graph_state(&self) -> JsonRpcResult<SyncGraphStates>;

    #[rpc(name = "cfx_sendTransaction")]
    fn send_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> BoxFuture<H256>;

    /// Returns accounts list.
    #[rpc(name = "accounts")]
    fn accounts(&self) -> JsonRpcResult<Vec<RpcAddress>>;

    /// Create a new account
    #[rpc(name = "new_account")]
    fn new_account(&self, password: String) -> JsonRpcResult<RpcAddress>;

    /// Unlock an account
    #[rpc(name = "unlock_account")]
    fn unlock_account(
        &self, address: RpcAddress, password: String, duration: Option<U128>,
    ) -> JsonRpcResult<bool>;

    /// Lock an account
    #[rpc(name = "lock_account")]
    fn lock_account(&self, address: RpcAddress) -> JsonRpcResult<bool>;

    #[rpc(name = "sign")]
    fn sign(
        &self, data: RpcBytes, address: RpcAddress, password: Option<String>,
    ) -> JsonRpcResult<H520>;

    #[rpc(name = "cfx_signTransaction")]
    fn sign_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> JsonRpcResult<String>;

    #[rpc(name = "cfx_getEpochReceipts")]
    fn epoch_receipts(
        &self, epoch: BlockHashOrEpochNumber,
    ) -> JsonRpcResult<Option<Vec<Vec<RpcReceipt>>>>;
}
