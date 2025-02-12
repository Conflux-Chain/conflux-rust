use cfx_addr::Network;
use cfx_execute_helper::exec_tracer::{
    construct_parity_trace, TraceWithPosition,
};
use cfx_rpc_cfx_impl::TraceHandler;
use cfx_rpc_cfx_types::{
    trace::Action as RpcAction,
    trace_eth::{LocalizedTrace as EthLocalizedTrace, Res as EthRes},
};
use cfx_rpc_eth_api::TraceApiServer;
use cfx_rpc_eth_types::{BlockNumber, LocalizedTrace, TraceFilter};
use cfx_types::H256;
use cfx_util_macros::unwrap_option_or_return_result_none as unwrap_or_return;
use cfxcore::{errors::Result as CoreResult, SharedConsensusGraph};
use jsonrpc_core::Error as RpcError;
use jsonrpsee::core::RpcResult;
use log::warn;
use primitives::EpochNumber;

pub struct TraceApi {
    trace_handler: TraceHandler,
}

impl TraceApi {
    pub fn new(consensus: SharedConsensusGraph, network: Network) -> TraceApi {
        let trace_handler = TraceHandler::new(network, consensus);
        TraceApi { trace_handler }
    }

    pub fn block_traces(
        &self, block_number: BlockNumber,
    ) -> CoreResult<Option<Vec<LocalizedTrace>>> {
        let phantom_block = match block_number {
            BlockNumber::Hash { hash, .. } => self
                .trace_handler
                .consensus_graph()
                .get_phantom_block_by_hash(
                    &hash, true, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?,

            _ => self
                .trace_handler
                .consensus_graph()
                .get_phantom_block_by_number(
                    block_number.try_into()?,
                    None,
                    true, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?,
        };

        unwrap_or_return!(phantom_block);

        let mut eth_traces = Vec::new();
        let block_number = phantom_block.pivot_header.height();
        let block_hash = phantom_block.pivot_header.hash();

        for (idx, tx_traces) in phantom_block.traces.into_iter().enumerate() {
            let tx_hash = phantom_block.transactions[idx].hash();
            // convert traces
            let trace_pairs =
                construct_parity_trace(&tx_traces).map_err(|e| {
                    warn!("Internal error on trace reconstruction: {}", e);
                    RpcError::internal_error()
                })?;

            for TraceWithPosition {
                action,
                result,
                child_count,
                trace_path,
            } in trace_pairs
            {
                let mut eth_trace = LocalizedTrace {
                    action: RpcAction::try_from(
                        action.action.clone(),
                        self.trace_handler.network,
                    )
                    .map_err(|_| RpcError::internal_error())?
                    .try_into()
                    .map_err(|_| RpcError::internal_error())?,
                    result: EthRes::None,
                    trace_address: trace_path,
                    subtraces: child_count,
                    transaction_position: Some(idx),
                    transaction_hash: Some(tx_hash),
                    block_number,
                    block_hash,
                    // action and its result should have the same `valid`.
                    valid: action.valid,
                };

                eth_trace.set_result(
                    RpcAction::try_from(
                        result.action.clone(),
                        self.trace_handler.network,
                    )
                    .map_err(|_| RpcError::internal_error())?,
                )?;

                eth_traces.push(eth_trace);
            }
        }

        Ok(Some(eth_traces))
    }

    pub fn filter_traces(
        &self, filter: TraceFilter,
    ) -> CoreResult<Vec<LocalizedTrace>> {
        // TODO(lpl): Use `TransactionExecTraces::filter_trace_pairs` to avoid
        // pairing twice.
        let primitive_filter = filter.into_primitive()?;

        let traces =
            match self.trace_handler.filter_traces_impl(primitive_filter)? {
                None => return Ok(Vec::new()),
                Some(traces) => traces,
            };

        Ok(TraceHandler::to_eth_traces(traces)?)
    }

    pub fn transaction_traces(
        &self, tx_hash: H256,
    ) -> CoreResult<Option<Vec<EthLocalizedTrace>>> {
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
            .map_err(RpcError::invalid_params)?;

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
        let mut eth_traces = Vec::new();

        let trace_pairs = construct_parity_trace(&tx_traces).map_err(|e| {
            warn!("Internal error on trace reconstruction: {}", e);
            RpcError::internal_error()
        })?;

        for TraceWithPosition {
            action,
            result,
            child_count,
            trace_path,
        } in trace_pairs
        {
            let mut eth_trace = EthLocalizedTrace {
                action: RpcAction::try_from(
                    action.action.clone(),
                    self.trace_handler.network,
                )
                .map_err(|_| RpcError::internal_error())?
                .try_into()
                .map_err(|_| RpcError::internal_error())?,
                result: EthRes::None,
                trace_address: trace_path,
                subtraces: child_count,
                transaction_position: Some(id),
                transaction_hash: Some(tx.hash()),
                block_number: epoch_num,
                block_hash: phantom_block.pivot_header.hash(),
                // action and its result should have the same `valid`.
                valid: action.valid,
            };

            eth_trace.set_result(
                RpcAction::try_from(
                    result.action.clone(),
                    self.trace_handler.network,
                )
                .map_err(|_| RpcError::internal_error())?,
            )?;

            eth_traces.push(eth_trace);
        }

        Ok(Some(eth_traces))
    }
}

#[async_trait::async_trait]
impl TraceApiServer for TraceApi {
    async fn block_traces(
        &self, block_number: BlockNumber,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>> {
        self.block_traces(block_number).map_err(|err| err.into())
    }

    async fn filter_traces(
        &self, filter: TraceFilter,
    ) -> RpcResult<Vec<LocalizedTrace>> {
        self.filter_traces(filter).map_err(|err| err.into())
    }

    async fn transaction_traces(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<Vec<EthLocalizedTrace>>> {
        self.transaction_traces(tx_hash).map_err(|err| err.into())
    }
}
