// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::LocalizedBlockTrace;
use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        traits::trace::Trace,
        types::{
            Action as RpcAction, LocalizedTrace as RpcLocalizedTrace,
            LocalizedTrace, TraceFilter as RpcTraceFilter, TraceFilter,
        },
        RpcResult,
    },
};
use cfx_addr::Network;
use cfx_types::H256;
use cfxcore::{
    block_data_manager::DataVersionTuple, trace::trace::ExecTrace,
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
        let transaction_hashes = match self
            .data_man
            .block_by_hash(&block_hash, true /* update_cache */)
        {
            None => return Ok(None),
            Some(block) => {
                block.transactions.iter().map(|tx| tx.hash()).collect()
            }
        };

        match self.data_man.block_traces_by_hash(&block_hash) {
            None => Ok(None),
            Some(DataVersionTuple(pivot_hash, traces)) => {
                let epoch_number = self
                    .data_man
                    .block_height_by_hash(&pivot_hash)
                    .ok_or("pivot block missing")?;
                match LocalizedBlockTrace::from(
                    traces,
                    block_hash,
                    pivot_hash,
                    epoch_number,
                    transaction_hashes,
                    self.network,
                ) {
                    Ok(t) => Ok(Some(t)),
                    Err(e) => bail!(format!(
                        "Traces not found for block {:?}: {:?}",
                        block_hash, e
                    )),
                }
            }
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
    ) -> RpcResult<Option<Vec<RpcLocalizedTrace>>> {
        Ok(self
            .data_man
            .transaction_index_by_hash(tx_hash, true /* update_cache */)
            .and_then(|tx_index| {
                self.data_man
                    .transactions_traces_by_block_hash(&tx_index.block_hash)
                    .and_then(|(pivot_hash, traces)| {
                        traces
                            .into_iter()
                            .nth(tx_index.index)
                            .map(Into::<Vec<ExecTrace>>::into)
                            .map(|traces| {
                                traces
                                    .into_iter()
                                    .map(|trace| RpcLocalizedTrace {
                                        action: RpcAction::try_from(
                                            trace.action,
                                            self.network,
                                        )
                                        .expect("local address convert error"),
                                        epoch_hash: Some(pivot_hash),
                                        epoch_number: Some(
                                            self.data_man
                                                .block_height_by_hash(
                                                    &pivot_hash,
                                                )
                                                .expect("pivot block missing")
                                                .into(),
                                        ),
                                        block_hash: Some(tx_index.block_hash),
                                        transaction_position: Some(
                                            tx_index.index.into(),
                                        ),
                                        transaction_hash: Some(*tx_hash),
                                    })
                                    .collect()
                            })
                    })
            }))
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
