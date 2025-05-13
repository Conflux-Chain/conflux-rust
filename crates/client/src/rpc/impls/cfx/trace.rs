// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        traits::trace::Trace,
        types::{
            EpochNumber as RpcEpochNumber, LocalizedBlockTrace, LocalizedTrace,
            TraceFilter as RpcTraceFilter,
        },
        CoreResult,
    },
};
use cfx_addr::Network;
use cfx_execute_helper::exec_tracer::TraceFilter as PrimitiveTraceFilter;
use cfx_parity_trace_types::LocalizedTrace as PrimitiveLocalizedTrace;
use cfx_rpc_cfx_impl::TraceHandler as CfxTraceHandler;
use cfx_rpc_cfx_types::trace::EpochTrace;
use cfx_types::H256;

use cfxcore::{ConsensusGraph, SharedConsensusGraph};
use jsonrpc_core::Result as JsonRpcResult;

#[derive(Clone)]
pub struct TraceHandler {
    pub(crate) inner: CfxTraceHandler,
}

impl TraceHandler {
    pub fn new(network: Network, consensus: SharedConsensusGraph) -> Self {
        TraceHandler {
            inner: CfxTraceHandler::new(network, consensus),
        }
    }

    pub(crate) fn consensus_graph(&self) -> &ConsensusGraph {
        self.inner.consensus_graph()
    }

    pub(crate) fn filter_primitives_traces_impl(
        &self, filter: PrimitiveTraceFilter,
    ) -> CoreResult<Option<Vec<PrimitiveLocalizedTrace>>> {
        self.inner.filter_primitives_traces_impl(filter)
    }
}

impl Trace for TraceHandler {
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>> {
        into_jsonrpc_result(self.inner.block_traces_impl(block_hash))
    }

    fn filter_traces(
        &self, filter: RpcTraceFilter,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        let primitive_filter = filter.into_primitive()?;
        into_jsonrpc_result(self.inner.filter_traces_impl(primitive_filter))
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        into_jsonrpc_result(Ok(self.inner.transaction_trace_impl(&tx_hash)))
    }

    fn epoch_traces(&self, epoch: RpcEpochNumber) -> JsonRpcResult<EpochTrace> {
        into_jsonrpc_result(self.inner.epoch_trace_impl(epoch.into_primitive()))
    }
}
