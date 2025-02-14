use cfx_addr::Network;
use cfx_parity_trace_types::{
    ExecTrace, LocalizedTrace as PrimitiveLocalizedTrace,
};
use cfx_rpc_cfx_types::{
    trace::Action as RpcAction,
    trace_eth::{LocalizedTrace as EthLocalizedTrace, Res as EthRes},
};
use cfx_types::H256;

use super::matcher::{construct_parity_trace, TraceWithPosition};

pub fn into_eth_localized_traces(
    tx_traces: &[ExecTrace], block_number: u64, block_hash: H256,
    tx_hash: H256, tx_idx: usize, network: Network,
) -> Result<Vec<EthLocalizedTrace>, String> {
    let mut eth_traces = vec![];
    for TraceWithPosition {
        action,
        result,
        child_count,
        trace_path,
    } in construct_parity_trace(&tx_traces)?
    {
        let mut eth_trace = EthLocalizedTrace {
            action: RpcAction::try_from(action.action.clone(), network)?
                .try_into()?,
            result: EthRes::None,
            trace_address: trace_path,
            subtraces: child_count,
            transaction_position: Some(tx_idx),
            transaction_hash: Some(tx_hash),
            block_number,
            block_hash,
            // action and its result should have the same `valid`.
            valid: action.valid,
        };

        eth_trace
            .set_result(RpcAction::try_from(result.action.clone(), network)?)
            .expect("`construct_parity_trace` has guarantee the consistency");

        eth_traces.push(eth_trace);
    }

    Ok(eth_traces)
}

pub fn primitive_traces_to_eth_localized_traces(
    primitive_traces: &[PrimitiveLocalizedTrace], network: Network,
) -> Result<Vec<EthLocalizedTrace>, String> {
    use slice_group_by::GroupBy;

    let mut traces = vec![];
    for tx_traces in
        primitive_traces.linear_group_by_key(|x| x.transaction_hash)
    {
        let first_tx = tx_traces.first().unwrap();
        let tx_exec_traces: Vec<_> = tx_traces
            .iter()
            .map(|x| ExecTrace {
                action: x.action.clone(),
                valid: x.valid,
            })
            .collect();
        let eth_traces = into_eth_localized_traces(
            &tx_exec_traces,
            first_tx.epoch_number.as_u64(),
            first_tx.epoch_hash,
            first_tx.transaction_hash,
            first_tx.transaction_position.as_usize(),
            network,
        )?;
        traces.extend(eth_traces);
    }
    Ok(traces)
}
