use cfx_addr::Network;
use cfx_rpc_cfx_impl::TraceHandler;
use cfx_rpc_cfx_types::trace_eth::LocalizedTrace as EthLocalizedTrace;
use cfx_rpc_common_impl::trace::{
    into_eth_localized_traces, primitive_traces_to_eth_localized_traces,
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
        let network = self.trace_handler.network;

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
                RpcError::internal_error()
            })?;
            eth_traces.extend(tx_eth_traces);
        }

        Ok(Some(eth_traces))
    }

    pub fn filter_traces(
        &self, filter: TraceFilter,
    ) -> CoreResult<Vec<LocalizedTrace>> {
        let primitive_filter = filter.into_primitive()?;

        let Some(primitive_traces) = self
            .trace_handler
            .filter_primitives_traces_impl(primitive_filter)?
        else {
            return Ok(vec![]);
        };

        let traces = primitive_traces_to_eth_localized_traces(
            &primitive_traces,
            self.trace_handler.network,
        )
        .map_err(|e| {
            warn!("Internal error on trace reconstruction: {}", e);
            RpcError::internal_error()
        })?;
        Ok(traces)
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

        let network = self.trace_handler.network;

        let eth_traces = into_eth_localized_traces(
            &tx_traces.0,
            epoch_num,
            phantom_block.pivot_header.hash(),
            tx.hash(),
            id,
            network,
        )
        .map_err(|e| {
            warn!("Internal error on trace reconstruction: {}", e);
            RpcError::internal_error()
        })?;

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
