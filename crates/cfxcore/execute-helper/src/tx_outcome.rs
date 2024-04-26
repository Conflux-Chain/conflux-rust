use cfx_executor::{
    executive::ExecutionOutcome, internal_contract::make_staking_events,
};
use cfx_types::{H256, U256};
use pow_types::StakingEvent;
use primitives::Receipt;

use crate::observer::geth_tracer::GethTraceKey;
use alloy_rpc_types_trace::geth::GethTrace;

use super::{
    observer::exec_tracer::{ExecTrace, ExecTraceKey},
    phantom_tx::{recover_phantom, PhantomTransaction},
};

pub struct ProcessTxOutcome {
    pub receipt: Receipt,
    pub phantom_txs: Vec<PhantomTransaction>,
    pub tx_traces: Vec<ExecTrace>,
    pub tx_staking_events: Vec<StakingEvent>,
    pub tx_exec_error_msg: String,
    pub consider_repacked: bool,
    pub geth_trace: Option<GethTrace>,
}

fn tx_traces(outcome: &ExecutionOutcome) -> Vec<ExecTrace> {
    outcome
        .try_as_executed()
        .and_then(|executed| executed.ext_result.get::<ExecTraceKey>().cloned())
        .unwrap_or_default()
}

fn geth_traces(outcome: &ExecutionOutcome) -> Option<GethTrace> {
    outcome
        .try_as_executed()
        .and_then(|executed| executed.ext_result.get::<GethTraceKey>().cloned())
}

pub fn make_process_tx_outcome(
    outcome: ExecutionOutcome, accumulated_gas_used: &mut U256, tx_hash: H256,
) -> ProcessTxOutcome {
    let tx_traces = tx_traces(&outcome);
    let geth_trace = geth_traces(&outcome);
    let tx_exec_error_msg = outcome.error_message();
    let consider_repacked = outcome.consider_repacked();
    let receipt = outcome.make_receipt(accumulated_gas_used);

    let tx_staking_events = make_staking_events(receipt.logs());

    let phantom_txs = recover_phantom(&receipt.logs(), tx_hash);

    ProcessTxOutcome {
        receipt,
        phantom_txs,
        tx_traces,
        tx_staking_events,
        tx_exec_error_msg,
        consider_repacked,
        geth_trace,
    }
}
