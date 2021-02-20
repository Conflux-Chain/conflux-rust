// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::LocalizedBlockTrace;
use crate::{
    common::delegate_convert,
    rpc::{
        traits::trace::Trace,
        types::{
            LocalizedTrace as RpcLocalizedTrace, TraceFilter as RpcTraceFilter,
        },
        RpcError,
    },
};
use cfx_addr::Network;
use cfx_types::H256;
use cfxcore::{BlockDataManager, ConsensusGraph, SharedConsensusGraph};
use jsonrpc_core::{Error as JsonRpcError, Result as JsonRpcResult};
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
}

impl Trace for TraceHandler {
    fn block_traces(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<LocalizedBlockTrace>> {
        match self.data_man.block_traces_by_hash(&block_hash) {
            None => Ok(None),
            Some(t) => match LocalizedBlockTrace::from(t, self.network) {
                Ok(t) => Ok(Some(t)),
                Err(e) => Err(JsonRpcError::invalid_params(format!(
                    "Traces not found for block {:?}: {:?}",
                    block_hash, e
                ))),
            },
        }
    }

    fn filter_traces(
        &self, rpc_filter: RpcTraceFilter,
    ) -> JsonRpcResult<Option<Vec<RpcLocalizedTrace>>> {
        let filter = rpc_filter.into_primitive()?;
        let consensus_graph = self.consensus_graph();
        let traces: Vec<_> = consensus_graph
            .filter_traces(filter)
            .map_err(|e| delegate_convert::Into::into(RpcError::from(e)))?
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
}
