// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::super::types::{
    Transaction as RpcTransaction, H256 as RpcH256,
};
use jsonrpc_core::Result as RpcResult;
use jsonrpc_derive::rpc;
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails,
};
use std::collections::BTreeMap;

#[rpc]
pub trait DebugRpc {
    #[rpc(name = "txpool_status")]
    fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;

    #[rpc(name = "tx_inspect")]
    fn tx_inspect(&self, hash: RpcH256) -> RpcResult<BTreeMap<String, String>>;

    #[rpc(name = "txpool_inspect")]
    fn txpool_inspect(
        &self,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    >;

    #[rpc(name = "txpool_content")]
    fn txpool_content(
        &self,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    >;

    #[rpc(name = "clear_tx_pool")]
    fn clear_tx_pool(&self) -> RpcResult<()>;

    #[rpc(name = "net_throttling")]
    fn net_throttling(&self) -> RpcResult<throttling::Service>;

    #[rpc(name = "net_node")]
    fn net_node(&self, node_id: NodeId) -> RpcResult<Option<(String, Node)>>;

    #[rpc(name = "net_sessions")]
    fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>>;

    #[rpc(name = "net_high_priority_packets")]
    fn net_high_priority_packets(&self) -> RpcResult<usize>;

    #[rpc(name = "current_sync_phase")]
    fn current_sync_phase(&self) -> RpcResult<String>;
}
