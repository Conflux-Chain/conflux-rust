// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::Network;
use cfx_execute_helper::exec_tracer::TraceFilter as PrimitiveTraceFilter;
use cfx_types::{Space, H256};
use cfx_util_macros::bail;
use cfxcore::{
    block_data_manager::DataVersionTuple, errors::Result as CoreResult,
    BlockDataManager, ConsensusGraph, ConsensusGraphTrait,
    SharedConsensusGraph,
};
use jsonrpc_core::{Error as JsonRpcError, Result as JsonRpcResult};
use log::error;
use primitives::EpochNumber;
use std::{convert::TryInto, sync::Arc};

use cfx_rpc_cfx_types::{
    trace::{
        Action as RpcAction, EpochTrace, LocalizedBlockTrace, LocalizedTrace,
        LocalizedTrace as RpcLocalizedTrace,
    },
    trace_eth::LocalizedTrace as EthLocalizedTrace,
};

#[derive(Clone)]
pub struct TraceHandler {
    pub data_man: Arc<BlockDataManager>,
    pub consensus: SharedConsensusGraph,
    pub network: Network,
}

impl TraceHandler {
    pub fn new(network: Network, consensus: SharedConsensusGraph) -> Self {
        TraceHandler {
            data_man: consensus.get_data_manager().clone(),
            consensus,
            network,
        }
    }

    pub fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    pub fn block_traces_impl(
        &self, block_hash: H256,
    ) -> CoreResult<Option<LocalizedBlockTrace>> {
        // Note: an alternative to `into_jsonrpc_result` is the delegate! macro.
        let block = match self
            .data_man
            .block_by_hash(&block_hash, true /* update_cache */)
        {
            None => return Ok(None),
            Some(block) => block,
        };

        match self.data_man.block_traces_by_hash(&block_hash) {
            None => Ok(None),
            Some(DataVersionTuple(pivot_hash, traces)) => {
                let traces = traces.filter_space(Space::Native);
                let epoch_number = self
                    .data_man
                    .block_height_by_hash(&pivot_hash)
                    .ok_or("pivot block missing")?;
                match LocalizedBlockTrace::from(
                    traces,
                    block_hash,
                    pivot_hash,
                    epoch_number,
                    &block.transactions,
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

    pub fn filter_traces_impl(
        &self, filter: PrimitiveTraceFilter,
    ) -> CoreResult<Option<Vec<RpcLocalizedTrace>>> {
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

    pub fn transaction_trace_impl(
        &self, tx_hash: &H256,
    ) -> Option<Vec<RpcLocalizedTrace>> {
        let tx_index = self
            .data_man
            .transaction_index_by_hash(tx_hash, true /* update_cache */)?;

        // FIXME(thegaram): do we support traces for phantom txs?
        if tx_index.is_phantom {
            return None;
        }

        let block = self.data_man.block_by_hash(&tx_index.block_hash, false)?;

        if block
            .transactions
            .get(tx_index.real_index)
            .map(|tx| tx.space() == Space::Ethereum)
            // This default value is just added in case.
            .unwrap_or(true)
        {
            // If it's a Ethereum space tx, we return `Ok(None)` here
            // instead of returning `Ok(Some(vec![]))` later.
            return None;
        }

        let (pivot_hash, block_traces) = self
            .data_man
            .transactions_traces_by_block_hash(&tx_index.block_hash)?;

        let traces = block_traces
            .into_iter()
            .nth(tx_index.real_index)?
            .filter_space(Space::Native)
            .0;

        let answer = traces
            .into_iter()
            .map(|trace| RpcLocalizedTrace {
                action: RpcAction::try_from(trace.action, self.network)
                    .expect("local address convert error"),
                valid: trace.valid,
                epoch_hash: Some(pivot_hash),
                epoch_number: Some(
                    self.data_man
                        .block_height_by_hash(&pivot_hash)
                        .expect("pivot block missing")
                        .into(),
                ),
                block_hash: Some(tx_index.block_hash),
                transaction_position: Some(
                    tx_index.rpc_index.unwrap_or(tx_index.real_index).into(),
                ),
                transaction_hash: Some(*tx_hash),
            })
            .collect();

        Some(answer)
    }

    pub fn epoch_trace_impl(
        &self, epoch_number: EpochNumber,
    ) -> CoreResult<EpochTrace> {
        // Make sure we use the same epoch_hash in two spaces. Using
        // epoch_number cannot guarantee the atomicity.
        let epoch_hash = self
            .consensus
            .get_hash_from_epoch_number(epoch_number.clone())?;

        Ok(EpochTrace::new(
            self.space_epoch_traces(Space::Native, epoch_hash)?,
            Self::to_eth_traces(
                self.space_epoch_traces(Space::Ethereum, epoch_hash)?,
            )?,
        ))
    }

    fn space_epoch_traces(
        &self, space: Space, epoch_hash: H256,
    ) -> CoreResult<Vec<LocalizedTrace>> {
        let consensus = self.consensus_graph();
        let epoch = consensus
            .get_block_epoch_number(&epoch_hash)
            .ok_or(JsonRpcError::internal_error())?;
        let mut trace_filter = PrimitiveTraceFilter::space_filter(space);
        trace_filter.from_epoch = EpochNumber::Number(epoch);
        trace_filter.to_epoch = EpochNumber::Number(epoch);
        let block_traces = consensus.collect_traces_single_epoch(
            &trace_filter,
            epoch,
            epoch_hash,
        )?;
        let traces = consensus
            .filter_block_traces(&trace_filter, block_traces)?
            .into_iter()
            .map(|trace| {
                RpcLocalizedTrace::from(trace, self.network)
                    .expect("Local address conversion should succeed")
            })
            .collect();
        Ok(traces)
    }

    pub fn to_eth_traces(
        traces: Vec<LocalizedTrace>,
    ) -> JsonRpcResult<Vec<EthLocalizedTrace>> {
        let mut eth_traces: Vec<EthLocalizedTrace> = Vec::new();
        let mut stack_index = Vec::new();
        let mut sublen_stack = Vec::new();

        for trace in traces {
            match &trace.action {
                RpcAction::Call(_) | RpcAction::Create(_) => {
                    if let Some(parent_subtraces) = sublen_stack.last_mut() {
                        *parent_subtraces += 1;
                    }

                    sublen_stack.push(0);
                    stack_index.push(eth_traces.len());

                    eth_traces.push(trace.try_into().map_err(|e| {
                        error!("eth trace conversion error: {:?}", e);
                        JsonRpcError::internal_error()
                    })?);
                }
                RpcAction::CallResult(_) | RpcAction::CreateResult(_) => {
                    let index = stack_index
                        .pop()
                        .ok_or(JsonRpcError::internal_error())?;

                    eth_traces[index].set_result(trace.action)?;

                    eth_traces[index].subtraces =
                        sublen_stack.pop().expect("stack_index matches");
                }
                RpcAction::InternalTransferAction(_) => {}
            }
        }

        if !stack_index.is_empty() {
            error!("eth::filter_traces: actions left unmatched");
            bail!(JsonRpcError::internal_error());
        }

        Ok(eth_traces)
    }
}
