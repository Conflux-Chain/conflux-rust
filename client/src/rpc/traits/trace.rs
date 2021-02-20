// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{LocalizedBlockTrace, LocalizedTrace};
use crate::rpc::types::TraceFilter;
use cfx_types::H256;
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;

/// Trace specific rpc interface.
#[rpc(server)]
pub trait Trace {
    /// Returns all traces produced at given block.
    #[rpc(name = "trace_block")]
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>>;

    /// Returns all traces produced at given block.
    #[rpc(name = "trace_filter")]
    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>>;
}
