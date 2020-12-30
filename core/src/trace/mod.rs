// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    trace::trace::{
        Action, Call, CallResult, Create, CreateResult, ExecTrace,
        InternalTransferAction,
    },
    vm::{ActionParams, ContractCreateResult, MessageCallResult},
};
use cfx_types::{Address, U256};

pub mod trace;

/// This trait is used by executive to build traces.
pub trait Tracer: Send {
    /// Data returned when draining the Tracer.
    type Output;

    /// Prepares call trace for given params.
    fn prepare_trace_call(&mut self, params: &ActionParams);

    /// Prepares call result trace
    fn prepare_trace_call_result(&mut self, result: &MessageCallResult);

    /// Prepares create trace for given params.
    fn prepare_trace_create(&mut self, params: &ActionParams);

    /// Prepares create result trace
    fn prepare_trace_create_result(&mut self, result: &ContractCreateResult);

    /// Prepares internal transfer action
    fn prepare_internal_transfer_action(
        &mut self, from: Address, to: Address, value: U256,
    );

    /// Consumes self and returns all traces.
    fn drain(self) -> Vec<Self::Output>;
}

/// Nonoperative tracer. Does not trace anything.
pub struct NoopTracer;

impl Tracer for NoopTracer {
    type Output = ExecTrace;

    fn prepare_trace_call(&mut self, _: &ActionParams) {}

    fn prepare_trace_call_result(&mut self, _: &MessageCallResult) {}

    fn prepare_trace_create(&mut self, _: &ActionParams) {}

    fn prepare_trace_create_result(&mut self, _: &ContractCreateResult) {}

    fn prepare_internal_transfer_action(
        &mut self, _: Address, _: Address, _: U256,
    ) {
    }

    fn drain(self) -> Vec<ExecTrace> { vec![] }
}

/// Simple executive tracer. Traces all calls and creates.
#[derive(Default)]
pub struct ExecutiveTracer {
    traces: Vec<ExecTrace>,
}

impl Tracer for ExecutiveTracer {
    type Output = ExecTrace;

    fn prepare_trace_call(&mut self, params: &ActionParams) {
        let trace = ExecTrace {
            action: Action::Call(Call::from(params.clone())),
        };
        self.traces.push(trace);
    }

    fn prepare_trace_call_result(&mut self, result: &MessageCallResult) {
        let trace = ExecTrace {
            action: Action::CallResult(CallResult::from(result)),
        };
        self.traces.push(trace);
    }

    fn prepare_trace_create(&mut self, params: &ActionParams) {
        let trace = ExecTrace {
            action: Action::Create(Create::from(params.clone())),
        };
        self.traces.push(trace);
    }

    fn prepare_trace_create_result(&mut self, result: &ContractCreateResult) {
        let trace = ExecTrace {
            action: Action::CreateResult(CreateResult::from(result)),
        };
        self.traces.push(trace);
    }

    fn prepare_internal_transfer_action(
        &mut self, from: Address, to: Address, value: U256,
    ) {
        let trace =
            ExecTrace {
                action: Action::InternalTransferAction(
                    InternalTransferAction { from, to, value },
                ),
            };
        self.traces.push(trace);
    }

    fn drain(self) -> Vec<ExecTrace> { self.traces }
}
