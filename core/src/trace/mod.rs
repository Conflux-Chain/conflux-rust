// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    trace::trace::{Action, Call, Create, ExecTrace},
    vm::ActionParams,
};

pub mod trace;

/// This trait is used by executive to build traces.
pub trait Tracer: Send {
    /// Data returned when draining the Tracer.
    type Output;

    /// Prepares call trace for given params.
    fn prepare_trace_call(&mut self, params: &ActionParams);

    /// Prepares create trace for given params.
    fn prepare_trace_create(&mut self, params: &ActionParams);

    /// Consumes self and returns all traces.
    fn drain(self) -> Vec<Self::Output>;
}

/// Nonoperative tracer. Does not trace anything.
pub struct NoopTracer;

impl Tracer for NoopTracer {
    type Output = ExecTrace;

    fn prepare_trace_call(&mut self, _: &ActionParams) {}

    fn prepare_trace_create(&mut self, _: &ActionParams) {}

    fn drain(self) -> Vec<ExecTrace> { vec![] }
}

/// Simple executive tracer. Traces all calls and creates. Ignores
/// delegatecalls.
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

    fn prepare_trace_create(&mut self, params: &ActionParams) {
        let trace = ExecTrace {
            action: Action::Create(Create::from(params.clone())),
        };
        self.traces.push(trace);
    }

    fn drain(self) -> Vec<ExecTrace> { self.traces }
}
