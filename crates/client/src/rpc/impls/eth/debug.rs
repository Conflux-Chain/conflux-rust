use std::{convert::TryInto, sync::Arc};

use crate::rpc::{
    error_codes::invalid_params_msg,
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
use cfxcore::{ConsensusGraph, ConsensusGraphTrait, SharedConsensusGraph};
use geth_tracer::to_alloy_h256;
use jsonrpc_core::Result as JsonRpcResult;
use primitives::{Block, BlockHeaderBuilder, EpochNumber};

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

    fn get_block_epoch_num(&self, block: BlockNumber) -> Result<u64, String> {
        let num = match block {
            BlockNumber::Num(block_number) => block_number,
            BlockNumber::Latest
            | BlockNumber::Safe
            | BlockNumber::Finalized => {
                let epoch_num = block.try_into().expect("should success");
                self.consensus_graph()
                    .get_height_from_epoch_number(epoch_num)?
            }
            BlockNumber::Hash {
                hash,
                require_canonical,
            } => self
                .consensus_graph()
                .get_block_epoch_number_with_pivot_check(
                    &hash,
                    require_canonical,
                )
                .map_err(|err| err.to_string())?,
            _ => return Err("not supported".to_string()),
        };
        Ok(num)
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
        let num = self
            .get_block_epoch_num(block)
            .map_err(|e| invalid_params_msg(&e))?;
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

    // TODO: implement state and block override
    fn debug_trace_call(
        &self, request: CallRequest, block_number: Option<BlockNumber>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> JsonRpcResult<GethTrace> {
        let opts = opts.unwrap_or_default();
        let block_num = block_number.unwrap_or_default();

        let epoch_num = self
            .get_block_epoch_num(block_num)
            .map_err(|e| invalid_params_msg(&e))?;

        // validate epoch state
        self.consensus_graph()
            .validate_stated_epoch(&EpochNumber::Number(epoch_num))
            .map_err(|e| invalid_params_msg(&e))?;

        let epoch_block_hashes = self
            .consensus_graph()
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch_num))
            .map_err(|e| invalid_params_msg(&e))?;
        let epoch_id =
            epoch_block_hashes.last().expect("should have block hash");

        // construct blocks from call_request
        let chain_id = self.consensus.best_chain_id();
        let signed_tx = request
            .sign_call(chain_id.in_evm_space())
            .map_err(|e| invalid_params_msg(&e))?;
        let epoch_blocks = self
            .consensus_graph()
            .data_man
            .blocks_by_hash_list(
                &epoch_block_hashes,
                true, /* update_cache */
            )
            .expect("blocks exist");
        let pivot_block = epoch_blocks.last().expect("should have block");
        let header = BlockHeaderBuilder::new()
            .with_base_price(pivot_block.block_header.base_price())
            .with_parent_hash(pivot_block.block_header.hash())
            .with_height(epoch_num + 1)
            .with_timestamp(pivot_block.block_header.timestamp() + 1)
            .with_gas_limit(*pivot_block.block_header.gas_limit())
            .build();
        let block = Block::new(header, vec![Arc::new(signed_tx)]);
        let blocks: Vec<Arc<Block>> = vec![Arc::new(block)];

        let traces = self.consensus_graph().collect_blocks_geth_trace(
            *epoch_id,
            epoch_num,
            &blocks,
            opts.tracing_options,
            None,
        )?;

        let res = traces.first().expect("should have trace");

        Ok(res.trace.clone())
    }
}
