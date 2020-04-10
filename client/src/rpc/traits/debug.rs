// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{
    Bytes as RpcBytes, ConsensusGraphStates, SyncGraphStates,
    Transaction as RpcTransaction, H160 as RpcH160, H256 as RpcH256,
    H520 as RpcH520, U128 as RpcU128,
};
use crate::rpc::types::SendTxRequest;
use jsonrpc_core::{BoxFuture, Result as JsonRpcResult};
use jsonrpc_derive::rpc;
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use std::collections::BTreeMap;

#[rpc(server)]
pub trait LocalRpc {
    #[rpc(name = "txpool_status")]
    fn txpool_status(&self) -> JsonRpcResult<BTreeMap<String, usize>>;

    #[rpc(name = "tx_inspect")]
    fn tx_inspect(
        &self, hash: RpcH256,
    ) -> JsonRpcResult<BTreeMap<String, String>>;

    #[rpc(name = "txpool_inspect")]
    fn txpool_inspect(
        &self,
    ) -> JsonRpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    >;

    #[rpc(name = "txpool_content")]
    fn txpool_content(
        &self,
    ) -> JsonRpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    >;

    #[rpc(name = "clear_tx_pool")]
    fn clear_tx_pool(&self) -> JsonRpcResult<()>;

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

    #[rpc(name = "send_transaction")]
    fn send_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> BoxFuture<RpcH256>;

    /// Returns accounts list.
    #[rpc(name = "accounts")]
    fn accounts(&self) -> JsonRpcResult<Vec<RpcH160>>;

    /// Create a new account
    #[rpc(name = "new_account")]
    fn new_account(&self, password: String) -> JsonRpcResult<RpcH160>;

    /// Unlock an account
    #[rpc(name = "unlock_account")]
    fn unlock_account(
        &self, address: RpcH160, password: String, duration: Option<RpcU128>,
    ) -> JsonRpcResult<bool>;

    /// Lock an account
    #[rpc(name = "lock_account")]
    fn lock_account(&self, address: RpcH160) -> JsonRpcResult<bool>;

    #[rpc(name = "sign")]
    fn sign(
        &self, data: RpcBytes, address: RpcH160, password: Option<String>,
    ) -> JsonRpcResult<RpcH520>;
}
