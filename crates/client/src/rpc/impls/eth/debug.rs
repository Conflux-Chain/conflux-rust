use std::convert::TryInto;

use crate::rpc::{
    errors::invalid_params_msg,
    traits::eth_space::debug::Debug,
    types::eth::{BlockNumber, CallRequest},
};
use alloy_rpc_types_trace::geth::{
    GethDebugBuiltInTracerType,
    GethDebugTracerType::{BuiltInTracer, JsTracer},
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, NoopFrame,
    TraceResult,
};
use cfx_types::{Space, H256};
use cfxcore::{ConsensusGraph, SharedConsensusGraph};
use geth_tracer::to_alloy_h256;
use jsonrpc_core::Result as JsonRpcResult;

pub struct GethDebugHandler {
    consensus: SharedConsensusGraph,
}

impl GethDebugHandler {
    pub fn new(consensus: SharedConsensusGraph) -> Self {
        GethDebugHandler { consensus }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }
}

impl Debug for GethDebugHandler {
    fn db_get(&self, _key: String) -> JsonRpcResult<Option<String>> {
        Ok(Some("To be implemented!".into()))
    }

    fn debug_trace_transaction(
        &self, hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<GethTrace> {
        let opts = opts.unwrap_or_default();

        // early return if tracer is not supported or NoopTracer is requested
        if let Some(tracer_type) = &opts.tracer {
            match tracer_type {
                BuiltInTracer(builtin_tracer) => match builtin_tracer {
                    GethDebugBuiltInTracerType::FourByteTracer => (),
                    GethDebugBuiltInTracerType::CallTracer => {
                        // pre check config
                        let _ = opts
                            .tracer_config
                            .clone()
                            .into_call_config()
                            .map_err(|e| {
                            invalid_params_msg(&e.to_string())
                        })?;
                        ()
                    }
                    GethDebugBuiltInTracerType::PreStateTracer => {
                        // pre check config
                        let _ = opts
                            .tracer_config
                            .clone()
                            .into_pre_state_config()
                            .map_err(|e| invalid_params_msg(&e.to_string()))?;
                        ()
                    }
                    GethDebugBuiltInTracerType::NoopTracer => {
                        return Ok(GethTrace::NoopTracer(NoopFrame::default()))
                    }
                    GethDebugBuiltInTracerType::MuxTracer => {
                        return Err(invalid_params_msg("not supported"))
                    }
                },
                JsTracer(_) => return Err(invalid_params_msg("not supported")),
            }
        }

        let tx_index = self
            .consensus
            .get_data_manager()
            .transaction_index_by_hash(&hash, false /* update_cache */)
            .ok_or(invalid_params_msg("invalid tx hash"))?;

        let epoch_num = self
            .consensus
            .get_block_epoch_number(&tx_index.block_hash)
            .ok_or(invalid_params_msg("invalid tx hash"))?;

        let epoch_traces = self
            .consensus_graph()
            .collect_epoch_geth_trace(epoch_num, Some(hash), opts)
            .map_err(|e| {
                invalid_params_msg(&format!("invalid tx hash: {e}"))
            })?;

        // filter by tx hash
        let trace = epoch_traces
            .into_iter()
            .find(|val| val.tx_hash == hash)
            .map(|val| val.trace)
            .ok_or(invalid_params_msg("trace generation failed"));

        trace
    }

    fn debug_trace_block_by_hash(
        &self, block_hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        let opts = opts.unwrap_or_default();
        let epoch_num = self
            .consensus_graph()
            .get_block_epoch_number_with_pivot_check(&block_hash, false)?;

        let epoch_traces = self
            .consensus_graph()
            .collect_epoch_geth_trace(epoch_num, None, opts)
            .map_err(|e| {
                invalid_params_msg(&format!("invalid tx hash: {e}"))
            })?;

        let result = epoch_traces
            .into_iter()
            .filter(|val| val.space == Space::Ethereum)
            .map(|val| TraceResult::Success {
                result: val.trace,
                tx_hash: Some(to_alloy_h256(val.tx_hash)),
            })
            .collect();
        Ok(result)
    }

    fn debug_trace_block_by_number(
        &self, block: BlockNumber, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        let opts = opts.unwrap_or_default();
        let num = match block {
            BlockNumber::Num(block_number) => block_number,
            BlockNumber::Latest
            | BlockNumber::Safe
            | BlockNumber::Finalized => {
                let epoch_num = block.try_into().expect("should success");
                self.consensus_graph()
                    .get_height_from_epoch_number(epoch_num)
                    .map_err(|msg| invalid_params_msg(&msg))?
            }
            BlockNumber::Hash {
                hash,
                require_canonical,
            } => self
                .consensus_graph()
                .get_block_epoch_number_with_pivot_check(
                    &hash,
                    require_canonical,
                )?,
            _ => return Err(invalid_params_msg("not supported")),
        };
        let epoch_traces = self
            .consensus_graph()
            .collect_epoch_geth_trace(num, None, opts)
            .map_err(|e| {
                invalid_params_msg(&format!("invalid tx hash: {e}"))
            })?;

        let result = epoch_traces
            .into_iter()
            .filter(|val| val.space == Space::Ethereum)
            .map(|val| TraceResult::Success {
                result: val.trace,
                tx_hash: Some(to_alloy_h256(val.tx_hash)),
            })
            .collect();
        Ok(result)
    }

    fn debug_trace_call(
        &self, request: CallRequest, block_number: Option<BlockNumber>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> JsonRpcResult<GethTrace> {
        let _ = request;
        let _ = block_number;
        let _ = opts;
        todo!("not implemented yet");
    }
}
