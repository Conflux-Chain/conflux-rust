use crate::rpc::{
    impls::cfx::TraceHandler,
    traits::eth_space::trace::Trace as EthTrace,
    types::eth::{
        BlockNumber, LocalizedTrace as EthLocalizedTrace,
        TraceFilter as EthTraceFilter,
    },
};
use cfx_rpc_common_impl::trace::{
    into_eth_localized_traces, primitive_traces_to_eth_localized_traces,
};
use cfx_types::H256;
use cfx_util_macros::unwrap_option_or_return_result_none as unwrap_or_return;
use jsonrpc_core::{Error as JsonRpcError, Result as JsonRpcResult};
use log::warn;
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

        let network = self.trace_handler.inner.network;

        for (idx, tx_traces) in phantom_block.traces.into_iter().enumerate() {
            let tx_hash = phantom_block.transactions[idx].hash();
            let tx_eth_traces = into_eth_localized_traces(
                &tx_traces.0,
                block_number,
                block_hash,
                tx_hash,
                idx,
                network,
            )
            .map_err(|e| {
                warn!("Internal error on trace reconstruction: {}", e);
                JsonRpcError::internal_error()
            })?;
            eth_traces.extend(tx_eth_traces);
        }

        Ok(Some(eth_traces))
    }

    fn filter_traces(
        &self, filter: EthTraceFilter,
    ) -> JsonRpcResult<Option<Vec<EthLocalizedTrace>>> {
        let primitive_filter = filter.into_primitive()?;

        let Some(primitive_traces) = self
            .trace_handler
            .filter_primitives_traces_impl(primitive_filter)?
        else {
            return Ok(None);
        };

        let traces = primitive_traces_to_eth_localized_traces(
            &primitive_traces,
            self.trace_handler.inner.network,
        )
        .map_err(|e| {
            warn!("Internal error on trace reconstruction: {}", e);
            JsonRpcError::internal_error()
        })?;
        Ok(Some(traces))
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> JsonRpcResult<Option<Vec<EthLocalizedTrace>>> {
        let tx_index =
            self.trace_handler.inner.data_man.transaction_index_by_hash(
                &tx_hash, false, /* update_cache */
            );

        unwrap_or_return!(tx_index);

        let epoch_num = self
            .trace_handler
            .inner
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

        let network = self.trace_handler.inner.network;

        let eth_traces = into_eth_localized_traces(
            &tx_traces.0,
            epoch_num,
            phantom_block.pivot_header.hash(),
            tx.hash,
            id,
            network,
        )
        .map_err(|e| {
            warn!("Internal error on trace reconstruction: {}", e);
            JsonRpcError::internal_error()
        })?;

        Ok(Some(eth_traces))
    }
}
