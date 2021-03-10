// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::LocalizedBlockTrace;
use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        traits::trace::Trace,
        types::{
            LocalizedTrace as RpcLocalizedTrace, LocalizedTrace,
            TraceFilter as RpcTraceFilter, TraceFilter,
        },
        RpcResult,
    },
};
use cfx_addr::Network;
use cfx_types::H256;
use cfxcore::{
    trace::trace::{ExecTrace, TransactionExecTraces},
    BlockDataManager, ConsensusGraph, SharedConsensusGraph,
};
use jsonrpc_core::Result as JsonRpcResult;
use std::sync::Arc;

pub struct TraceHandler {
    data_man: Arc<BlockDataManager>,
    consensus: SharedConsensusGraph,
    network: Network,
}

impl TraceHandler {
    pub fn new(
        data_man: Arc<BlockDataManager>, network: Network,
        consensus: SharedConsensusGraph,
    ) -> Self
    {
        TraceHandler {
            data_man,
            consensus,
            network,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    fn block_traces_impl(
        &self, block_hash: H256,
    ) -> RpcResult<Option<LocalizedBlockTrace>> {
        // Note: an alternative to `into_jsonrpc_result` is the delegate! macro.

        match self.data_man.block_traces_by_hash(&block_hash) {
            None => Ok(None),
            Some(t) => match LocalizedBlockTrace::from(t, self.network) {
                Ok(t) => Ok(Some(t)),
                Err(e) => bail!(format!(
                    "Traces not found for block {:?}: {:?}",
                    block_hash, e
                )),
            },
        }
    }

    fn filter_traces_impl(
        &self, rpc_filter: RpcTraceFilter,
    ) -> RpcResult<Option<Vec<RpcLocalizedTrace>>> {
        let filter = rpc_filter.into_primitive()?;
        let consensus_graph = self.consensus_graph();
        let traces: Vec<_> = consensus_graph
            .filter_traces(filter)?
            .into_iter()
            .map(|trace| {
                RpcLocalizedTrace::from(trace, self.network)
                    .expect("Local address conversion should succeed")
            })
            .collect();
        if traces.is_empty() {
            Ok(None)
        } else {
            Ok(Some(traces))
        }
    }

    fn transaction_trace_impl(
        &self, tx_hash: &H256,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>> {
        match self
            .data_man
            .transaction_index_by_hash(tx_hash, true /* update_cache */)
        {
            None => Ok(None),
            Some(tx_index) => {
                match self.data_man.block_traces_by_hash(&tx_index.block_hash) {
                    None => bail!(format!(
                        "Trace not found for transaction {:?}: tx_index={:?}",
                        tx_hash, tx_index,
                    )),
                    Some(block_traces) => {
                        let mut block_traces: Vec<TransactionExecTraces> =
                            block_traces.into();
                        if tx_index.index <= block_traces.len() {
                            bail!(format!("Tx index and trace unmatch: index={} trace_len={}",
                             tx_index.index, block_traces.len()));
                        }
                        let tx_traces: Vec<ExecTrace> =
                            block_traces.swap_remove(tx_index.index).into();
                        if tx_traces.is_empty() {
                            Ok(None)
                        } else {
                            Ok(Some(
                                tx_traces
                                    .into_iter()
                                    .map(|trace| {
                                        RpcLocalizedTrace::from(
                                            trace,
                                            self.network,
                                        ).expect("Local address conversion should succeed")
                                    })
                                    .collect()
                            ))
                        }
                    }
                }
            }
        }
    }
}

impl Trace for TraceHandler {
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>> {
        into_jsonrpc_result(self.block_traces_impl(block_hash))
    }

    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        into_jsonrpc_result(self.filter_traces_impl(filter))
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        into_jsonrpc_result(self.transaction_trace_impl(&tx_hash))
    }
}
