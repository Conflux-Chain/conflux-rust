use super::VmObserve;
use crate::{
    executive::ExecutiveResult,
    observer::trace::{
        Action, Call, CallResult, Create, CreateResult, ExecTrace,
        InternalTransferAction,
    },
    vm::{ActionParams, Result as VmResult},
};
pub use cfx_state::tracer::{AddressPocket, StateTracer};
use cfx_types::U256;

/// Simple executive tracer. Traces all calls and creates.
#[derive(Default)]
pub struct ExecutiveTracer {
    traces: Vec<Action>,
    valid_indices: CheckpointLog<usize>,
}

impl StateTracer for ExecutiveTracer {
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

    fn checkpoint(&mut self) { self.valid_indices.checkpoint(); }

    fn discard_checkpoint(&mut self) {
        self.valid_indices.discard_checkpoint();
    }

    fn revert_to_checkpoint(&mut self) {
        self.valid_indices.revert_checkpoint();
    }
}

impl VmObserve for ExecutiveTracer {
    fn record_call(&mut self, params: &ActionParams) {
        let action = Action::Call(Call::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());

        self.traces.push(action);
    }

    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let action = Action::CallResult(CallResult::from(result));
        let success = matches!(
            result,
            Ok(ExecutiveResult {
                apply_state: true, ..
            })
        );

        self.valid_indices.push(self.traces.len());
        if success {
            self.valid_indices.discard_checkpoint();
        } else {
            self.valid_indices.revert_checkpoint();
        }
        self.traces.push(action);
    }

    fn record_create(&mut self, params: &ActionParams) {
        let action = Action::Create(Create::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
    }

    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let action = Action::CreateResult(CreateResult::from(result));
        let success = matches!(
            result,
            Ok(ExecutiveResult {
                apply_state: true, ..
            })
        );

        self.valid_indices.push(self.traces.len());
        if success {
            self.valid_indices.discard_checkpoint();
        } else {
            self.valid_indices.revert_checkpoint();
        }
        self.traces.push(action);
    }
}

impl ExecutiveTracer {
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

#[derive(Default)]
struct CheckpointLog<T> {
    data: Vec<T>,
    checkpoints: Vec<usize>,
}

impl<T> CheckpointLog<T> {
    fn push(&mut self, item: T) { self.data.push(item); }

    fn checkpoint(&mut self) { self.checkpoints.push(self.data.len()); }

    fn revert_checkpoint(&mut self) {
        let start = self.checkpoints.pop().unwrap();
        self.data.truncate(start);
    }

    fn discard_checkpoint(&mut self) { self.checkpoints.pop().unwrap(); }

    fn drain(self) -> Vec<T> { self.data }
}
