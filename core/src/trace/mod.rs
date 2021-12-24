// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::ExecutiveResult,
    trace::trace::{
        Action, Call, CallResult, Create, CreateResult, ExecTrace,
        InternalTransferAction,
    },
    vm::{ActionParams, Result as VmResult},
};
pub use cfx_state::tracer::{AddressPocket, InternalTransferTracer};
use cfx_types::U256;

pub mod error_unwind;
pub mod trace;
pub mod trace_filter;

pub use error_unwind::ErrorUnwind;

/// This trait is used by executive to build traces.
pub trait Tracer: InternalTransferTracer {
    /// Prepares call trace for given params.
    fn prepare_trace_call(&mut self, params: &ActionParams);

    /// Prepares call result trace
    fn prepare_trace_call_result(&mut self, result: &VmResult<ExecutiveResult>);

    /// Prepares create trace for given params.
    fn prepare_trace_create(&mut self, params: &ActionParams);

    /// Prepares create result trace
    fn prepare_trace_create_result(
        &mut self, result: &VmResult<ExecutiveResult>,
    );

    /// Consumes self and returns all traces.
    fn drain(self) -> Vec<ExecTrace>;
}

/// Nonoperative tracer. Does not trace anything.
pub struct NoopTracer;

impl InternalTransferTracer for NoopTracer {
    fn prepare_internal_transfer_action(
        &mut self, _: AddressPocket, _: AddressPocket, _: U256,
    ) {
    }
}

impl Tracer for NoopTracer {
    fn prepare_trace_call(&mut self, _: &ActionParams) {}

    fn prepare_trace_call_result(&mut self, _: &VmResult<ExecutiveResult>) {}

    fn prepare_trace_create(&mut self, _: &ActionParams) {}

    fn prepare_trace_create_result(&mut self, _: &VmResult<ExecutiveResult>) {}

    fn drain(self) -> Vec<ExecTrace> { vec![] }
}

/// Simple executive tracer. Traces all calls and creates.
#[derive(Default)]
pub struct ExecutiveTracer {
    traces: Vec<Action>,
    valid_indices: CheckpointLog<usize>,
}

impl InternalTransferTracer for ExecutiveTracer {
    fn prepare_internal_transfer_action(
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

impl Tracer for ExecutiveTracer {
    fn prepare_trace_call(&mut self, params: &ActionParams) {
        let action = Action::Call(Call::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());

        self.traces.push(action);
    }

    fn prepare_trace_call_result(
        &mut self, result: &VmResult<ExecutiveResult>,
    ) {
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

    fn prepare_trace_create(&mut self, params: &ActionParams) {
        let action = Action::Create(Create::from(params.clone()));

        self.valid_indices.checkpoint();
        self.valid_indices.push(self.traces.len());
        self.traces.push(action);
    }

    fn prepare_trace_create_result(
        &mut self, result: &VmResult<ExecutiveResult>,
    ) {
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

    fn drain(self) -> Vec<ExecTrace> {
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
