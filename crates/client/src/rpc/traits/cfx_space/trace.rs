// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    EpochNumber, LocalizedBlockTrace, LocalizedTrace, TraceFilter,
};
use cfx_rpc_cfx_types::trace::EpochTrace;
use cfx_types::H256;
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;

/// Trace specific rpc interface.
#[rpc(server)]
pub trait Trace {
    /// Returns all traces produced at the given block.
    #[rpc(name = "trace_block")]
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>>;

    /// Returns all traces matching the provided filter.
    #[rpc(name = "trace_filter")]
    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>>;

    /// Returns all traces produced at the given transaction.
    #[rpc(name = "trace_transaction")]
    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>>;

    /// Return all traces of both spaces in an epoch.
    #[rpc(name = "trace_epoch")]
    fn epoch_traces(&self, epoch: EpochNumber) -> JsonRpcResult<EpochTrace>;
}
