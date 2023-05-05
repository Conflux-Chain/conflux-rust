// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::LocalizedBlockTrace;
use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        traits::{eth_space::trace::Trace as EthTrace, trace::Trace},
        types::{
            eth::{
                BlockNumber, LocalizedTrace as EthLocalizedTrace,
                Res as EthRes, TraceFilter as EthTraceFilter,
            },
            Action as RpcAction, EpochNumber as RpcEpochNumber, EpochTrace,
            LocalizedTrace as RpcLocalizedTrace, LocalizedTrace,
            TraceFilter as RpcTraceFilter,
        },
        RpcResult,
    },
};
use cfx_addr::Network;
use cfx_types::{Space, H256};
use cfxcore::{
    block_data_manager::DataVersionTuple,
    observer::trace_filter::TraceFilter as PrimitiveTraceFilter,
    BlockDataManager, ConsensusGraph, ConsensusGraphTrait,
    SharedConsensusGraph,
};
use jsonrpc_core::{Error as JsonRpcError, Result as JsonRpcResult};
use primitives::EpochNumber;
use std::{convert::TryInto, sync::Arc};

macro_rules! unwrap_or_return {
    ($e:ident) => {
        let $e = match $e {
            Some(x) => x,
            None => return Ok(None),
        };
    };
}

#[derive(Clone)]
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

    fn filter_traces_impl(
        &self, filter: PrimitiveTraceFilter,
    ) -> RpcResult<Option<Vec<RpcLocalizedTrace>>> {
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
                // FIXME(thegaram): do we support traces for phantom txs?
                if tx_index.is_phantom {
                    return None;
                }
                let block = match self
                    .data_man
                    .block_by_hash(&tx_index.block_hash, false)
                {
                    None => return None,
                    Some(block) => block,
                };
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

                self.data_man
                    .transactions_traces_by_block_hash(&tx_index.block_hash)
                    .and_then(|(pivot_hash, traces)| {
                        traces
                            .into_iter()
                            .nth(tx_index.real_index)
                            .map(|tx_trace| {
                                tx_trace.filter_space(Space::Native).0
                            })
                            .map(|traces| {
                                traces
                                    .into_iter()
                                    .map(|trace| RpcLocalizedTrace {
                                        action: RpcAction::try_from(
                                            trace.action,
                                            self.network,
                                        )
                                        .expect("local address convert error"),
                                        valid: trace.valid,
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
                                            tx_index
                                                .rpc_index
                                                .unwrap_or(tx_index.real_index)
                                                .into(),
                                        ),
                                        transaction_hash: Some(*tx_hash),
                                    })
                                    .collect()
                            })
                    })
            }))
    }

    fn epoch_trace_impl(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<EpochTrace> {
        // Make sure we use the same epoch_hash in two spaces. Using
        // epoch_number cannot guarantee the atomicity.
        let epoch_hash = self
            .consensus
            .get_hash_from_epoch_number(epoch_number.clone())?;

        Ok(EpochTrace::new(
            self.space_epoch_traces(Space::Native, epoch_hash)?,
            to_eth_traces(
                self.space_epoch_traces(Space::Ethereum, epoch_hash)?,
            )?,
        ))
    }

    fn space_epoch_traces(
        &self, space: Space, epoch_hash: H256,
    ) -> RpcResult<Vec<LocalizedTrace>> {
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
}

impl Trace for TraceHandler {
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>> {
        into_jsonrpc_result(self.block_traces_impl(block_hash))
    }

    fn filter_traces(
        &self, filter: RpcTraceFilter,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        let primitive_filter = filter.into_primitive()?;
        into_jsonrpc_result(self.filter_traces_impl(primitive_filter))
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<LocalizedTrace>>> {
        into_jsonrpc_result(self.transaction_trace_impl(&tx_hash))
    }

    fn epoch_traces(&self, epoch: RpcEpochNumber) -> JsonRpcResult<EpochTrace> {
        into_jsonrpc_result(self.epoch_trace_impl(epoch.into_primitive()))
    }
}

pub struct EthTraceHandler {
    pub trace_handler: TraceHandler,
}

impl EthTrace for EthTraceHandler {
    fn block_traces(
        &self, block_number: BlockNumber,
    ) -> JsonRpcResult<Option<Vec<EthLocalizedTrace>>> {
        let phantom_block = match block_number {
            BlockNumber::Hash { hash, .. } => self
                .trace_handler
                .consensus_graph()
                .get_phantom_block_by_hash(
                    &hash, true, /* include_traces */
                )
                .map_err(JsonRpcError::invalid_params)?,
            _ => self
                .trace_handler
                .consensus_graph()
                .get_phantom_block_by_number(
                    block_number.try_into()?,
                    None,
                    true, /* include_traces */
                )
                .map_err(JsonRpcError::invalid_params)?,
        };

        unwrap_or_return!(phantom_block);

        let mut eth_traces = Vec::new();
        let block_number = phantom_block.pivot_header.height();
        let block_hash = phantom_block.pivot_header.hash();

        for (idx, tx_traces) in phantom_block.traces.into_iter().enumerate() {
            let tx_hash = phantom_block.transactions[idx].hash();

            for (action, result, subtraces) in tx_traces
                .filter_trace_pairs(&PrimitiveTraceFilter::space_filter(
                    Space::Ethereum,
                ))
                .map_err(|_| JsonRpcError::internal_error())?
            {
                let mut eth_trace = EthLocalizedTrace {
                    action: RpcAction::try_from(
                        action.action,
                        self.trace_handler.network,
                    )
                    .map_err(|_| JsonRpcError::internal_error())?
                    .try_into()
                    .map_err(|_| JsonRpcError::internal_error())?,
                    result: EthRes::None,
                    trace_address: vec![],
                    subtraces,
                    transaction_position: Some(idx),
                    transaction_hash: Some(tx_hash),
                    block_number,
                    block_hash,
                    // action and its result should have the same `valid`.
                    valid: action.valid,
                };

                eth_trace.set_result(
                    RpcAction::try_from(
                        result.action,
                        self.trace_handler.network,
                    )
                    .map_err(|_| JsonRpcError::internal_error())?,
                )?;

                eth_traces.push(eth_trace);
            }
        }

        Ok(Some(eth_traces))
    }

    fn filter_traces(
        &self, filter: EthTraceFilter,
    ) -> JsonRpcResult<Option<Vec<EthLocalizedTrace>>> {
        // TODO(lpl): Use `TransactionExecTraces::filter_trace_pairs` to avoid
        // pairing twice.
        let primitive_filter = filter.into_primitive()?;

        let traces =
            match self.trace_handler.filter_traces_impl(primitive_filter)? {
                None => return Ok(None),
                Some(traces) => traces,
            };

        Ok(Some(to_eth_traces(traces)?))
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<EthLocalizedTrace>>> {
        let tx_index = self
            .trace_handler
            .data_man
            .transaction_index_by_hash(&tx_hash, false /* update_cache */);

        unwrap_or_return!(tx_index);

        let epoch_num = self
            .trace_handler
            .consensus
            .get_block_epoch_number(&tx_index.block_hash);

        unwrap_or_return!(epoch_num);

        let phantom_block = self
            .trace_handler
            .consensus_graph()
            .get_phantom_block_by_number(
                EpochNumber::Number(epoch_num),
                None,
                true, /* include_traces */
            )
            .map_err(JsonRpcError::invalid_params)?;

        unwrap_or_return!(phantom_block);

        // find tx corresponding to `tx_hash`
        let id = phantom_block
            .transactions
            .iter()
            .position(|tx| tx.hash() == tx_hash);

        unwrap_or_return!(id);

        let tx = &phantom_block.transactions[id];
        let tx_traces = phantom_block.traces[id].clone();

        // convert traces
        let trace_pairs = tx_traces
            .filter_trace_pairs(&PrimitiveTraceFilter::space_filter(
                Space::Ethereum,
            ))
            .map_err(JsonRpcError::invalid_params)?;

        let mut eth_traces = Vec::new();

        for (action, result, subtraces) in trace_pairs {
            let mut eth_trace = EthLocalizedTrace {
                action: RpcAction::try_from(
                    action.action,
                    self.trace_handler.network,
                )
                .map_err(|_| JsonRpcError::internal_error())?
                .try_into()
                .map_err(|_| JsonRpcError::internal_error())?,
                result: EthRes::None,
                trace_address: vec![],
                subtraces,
                transaction_position: Some(id),
                transaction_hash: Some(tx.hash()),
                block_number: epoch_num,
                block_hash: phantom_block.pivot_header.hash(),
                // action and its result should have the same `valid`.
                valid: action.valid,
            };

            eth_trace.set_result(
                RpcAction::try_from(result.action, self.trace_handler.network)
                    .map_err(|_| JsonRpcError::internal_error())?,
            )?;

            eth_traces.push(eth_trace);
        }

        Ok(Some(eth_traces))
    }
}

fn to_eth_traces(
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
                let index =
                    stack_index.pop().ok_or(JsonRpcError::internal_error())?;

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
