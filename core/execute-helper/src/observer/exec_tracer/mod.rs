mod action_types;
mod error_unwind;
mod filter;
mod phantom_traces;
mod trace_types;

#[cfg(test)]
mod tests;

pub use action_types::{
    Action, ActionType, Call, CallResult, Create, CreateResult,
    InternalTransferAction, Outcome,
};
pub use error_unwind::ErrorUnwind;
pub use filter::TraceFilter;
pub use phantom_traces::{
    recover_phantom_trace_for_call, recover_phantom_trace_for_withdraw,
    recover_phantom_traces,
};
pub use trace_types::{
    BlockExecTraces, ExecTrace, LocalizedTrace, TransactionExecTraces,
};

use super::utils::CheckpointLog;

use cfx_executor::{
    executive_observer::{
        AddressPocket, CallTracer, CheckpointTracer, DrainTrace,
        InternalTransferTracer,
    },
    stack::{FrameResult, FrameReturn},
};
use cfx_types::U256;
use cfx_vm_types::ActionParams;
use typemap::ShareDebugMap;

/// Simple executive tracer. Traces all calls and creates.
#[derive(Default)]
pub struct ExecTracer {
    traces: Vec<Action>,
    valid_indices: CheckpointLog<usize>,
}

impl DrainTrace for ExecTracer {
    fn drain_trace(self, map: &mut ShareDebugMap) {
        map.insert::<ExecTraceKey>(self.drain());
    }
}

pub struct ExecTraceKey;
impl typemap::Key for ExecTraceKey {
    type Value = Vec<ExecTrace>;
}

impl InternalTransferTracer for ExecTracer {
    fn trace_internal_transfer(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    ) {
        let action = Action::InternalTransferAction(InternalTransferAction {
            from,
            to,
            value,
        });

        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
    }
}

impl CheckpointTracer for ExecTracer {
    fn trace_checkpoint(&mut self) { self.valid_indices.checkpoint(); }

    fn trace_checkpoint_discard(&mut self) {
        self.valid_indices.discard_checkpoint();
    }

    fn trace_checkpoint_revert(&mut self) {
        self.valid_indices.revert_checkpoint();
    }
}

impl CallTracer for ExecTracer {
    fn record_call(&mut self, params: &ActionParams) {
        let action = Action::Call(Call::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());

        self.traces.push(action);
    }

    fn record_call_result(&mut self, result: &FrameResult) {
        let action = Action::CallResult(CallResult::from(result));
        let success = matches!(
            result,
            Ok(FrameReturn {
                apply_state: true, ..
            })
        );

        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
        if success {
            self.valid_indices.discard_checkpoint();
        } else {
            self.valid_indices.revert_checkpoint();
        }
    }

    fn record_create(&mut self, params: &ActionParams) {
        let action = Action::Create(Create::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
    }

    fn record_create_result(&mut self, result: &FrameResult) {
        let action = Action::CreateResult(CreateResult::from(result));
        let success = matches!(
            result,
            Ok(FrameReturn {
                apply_state: true, ..
            })
        );

        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
        if success {
            self.valid_indices.discard_checkpoint();
        } else {
            self.valid_indices.revert_checkpoint();
        }
    }
}

impl ExecTracer {
    pub fn drain(self) -> Vec<ExecTrace> {
        let mut validity: Vec<bool> = vec![false; self.traces.len()];
        for index in self.valid_indices.drain() {
            validity[index] = true;
        }
        self.traces
            .into_iter()
            .zip(validity.into_iter())
            .map(|(action, valid)| ExecTrace { action, valid })
            .collect()
    }
}
