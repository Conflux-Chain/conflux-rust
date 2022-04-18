// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::ExecutiveResult,
    vm::{ActionParams, Result as VmResult},
};
pub use cfx_state::tracer::{AddressPocket, StateTracer};

pub mod error_unwind;
pub mod gasman;
pub mod trace;
pub mod trace_filter;
pub mod tracer;

pub use error_unwind::ErrorUnwind;
pub use gasman::GasMan;
pub use tracer::ExecutiveTracer;

// FIXME(cx): Can the observer do not rely on the tracer?
/// This trait is used by executive to build traces.
pub trait VmObserve: StateTracer {
    /// Prepares call trace for given params.
    fn record_call(&mut self, params: &ActionParams);

    /// Prepares call result trace
    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>);

    /// Prepares create trace for given params.
    fn record_create(&mut self, params: &ActionParams);

    /// Prepares create result trace
    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>);
}

/// Nonoperative observer. Does not trace anything.
impl VmObserve for () {
    fn record_call(&mut self, _: &ActionParams) {}

    fn record_call_result(&mut self, _: &VmResult<ExecutiveResult>) {}

    fn record_create(&mut self, _: &ActionParams) {}

    fn record_create_result(&mut self, _: &VmResult<ExecutiveResult>) {}
}

impl<T> VmObserve for &mut T
where T: VmObserve
{
    fn record_call(&mut self, params: &ActionParams) {
        (*self).record_call(params);
    }

    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>) {
        (*self).record_call_result(result);
    }

    fn record_create(&mut self, params: &ActionParams) {
        (*self).record_create(params);
    }

    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>) {
        (*self).record_create_result(result);
    }
}

impl<S, T> VmObserve for (&mut S, &mut T)
where
    S: VmObserve,
    T: VmObserve,
{
    fn record_call(&mut self, params: &ActionParams) {
        self.0.record_call(params);
        self.1.record_call(params);
    }

    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>) {
        self.0.record_call_result(result);
        self.1.record_call_result(result);
    }

    fn record_create(&mut self, params: &ActionParams) {
        self.0.record_create(params);
        self.1.record_create(params);
    }

    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>) {
        self.0.record_create_result(result);
        self.1.record_create_result(result);
    }
}
