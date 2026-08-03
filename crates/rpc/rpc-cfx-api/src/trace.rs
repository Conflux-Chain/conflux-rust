// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    EpochNumber, LocalizedBlockTrace, LocalizedTrace, TraceFilter,
};
use cfx_rpc_eth_types::trace::EpochTrace;
use cfx_types::H256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Trace specific rpc interface.
#[rpc(server, namespace = "trace")]
pub trait Trace {
    /// Returns all traces produced at the given block.
    #[method(name = "block")]
    fn block_traces(
        &self, block_hash: H256,
    ) -> RpcResult<Option<LocalizedBlockTrace>>;

    /// Returns all traces matching the provided filter.
    #[method(name = "filter")]
    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;

    /// Returns all traces produced at the given transaction.
    #[method(name = "transaction")]
    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;

    /// Return all traces of both spaces in an epoch.
    #[method(name = "epoch")]
    fn epoch_traces(&self, epoch: EpochNumber)
        -> RpcResult<Option<EpochTrace>>;
}
