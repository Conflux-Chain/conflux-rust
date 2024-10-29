use crate::rpc::{
    errors::invalid_params_msg,
    traits::eth_space::debug::Debug,
    types::eth::{BlockNumber, TransactionRequest},
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
    TraceResult,
};
use cfx_rpc::DebugApi;
use cfx_types::{H256, U256};
use cfxcore::{ConsensusGraph, SharedConsensusGraph};
use jsonrpc_core::Result as JsonRpcResult;

pub struct GethDebugHandler {
    inner: DebugApi,
}

impl GethDebugHandler {
    pub fn new(
        consensus: SharedConsensusGraph, max_estimation_gas_limit: Option<U256>,
    ) -> Self {
        GethDebugHandler {
            inner: DebugApi::new(consensus.clone(), max_estimation_gas_limit),
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.inner.consensus_graph()
    }
}

impl Debug for GethDebugHandler {
    fn db_get(&self, _key: String) -> JsonRpcResult<Option<String>> {
        Ok(Some("To be implemented!".into()))
    }

    fn debug_trace_transaction(
        &self, hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<GethTrace> {
        self.inner
            .trace_transaction(hash, opts)
            .map_err(|err| err.into())
    }

    fn debug_trace_block_by_hash(
        &self, block_hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        let epoch_num = self
            .consensus_graph()
            .get_block_epoch_number_with_pivot_check(&block_hash, false)?;

        self.inner
            .trace_block_by_num(epoch_num, opts)
            .map_err(|err| err.into())
    }

    fn debug_trace_block_by_number(
        &self, block: BlockNumber, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>> {
        let num = self
            .inner
            .get_block_epoch_num(block)
            .map_err(|e| invalid_params_msg(&e))?;

        self.inner
            .trace_block_by_num(num, opts)
            .map_err(|err| err.into())
    }

    // TODO: implement state and block override
    fn debug_trace_call(
        &self, request: TransactionRequest, block_number: Option<BlockNumber>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> JsonRpcResult<GethTrace> {
        self.inner
            .trace_call(request, block_number, opts)
            .map_err(|err| err.into())
    }
}
