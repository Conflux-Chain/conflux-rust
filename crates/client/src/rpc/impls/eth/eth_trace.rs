use crate::rpc::{
    impls::cfx::TraceHandler,
    traits::eth_space::trace::Trace as EthTrace,
    types::{
        eth::{
            BlockNumber, LocalizedTrace as EthLocalizedTrace, Res as EthRes,
            TraceFilter as EthTraceFilter,
        },
        Action as RpcAction,
    },
};
use cfx_execute_helper::exec_tracer::TraceFilter as PrimitiveTraceFilter;
use cfx_types::{Space, H256};
use cfx_util_macros::unwrap_option_or_return_result_none as unwrap_or_return;
use jsonrpc_core::{Error as JsonRpcError, Result as JsonRpcResult};
use primitives::EpochNumber;

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

            for (action, result, subtraces) in
                PrimitiveTraceFilter::space_filter(Space::Ethereum)
                    .filter_trace_pairs(tx_traces)
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

        Ok(Some(TraceHandler::to_eth_traces(traces)?))
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
        let trace_pairs = PrimitiveTraceFilter::space_filter(Space::Ethereum)
            .filter_trace_pairs(tx_traces)
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
