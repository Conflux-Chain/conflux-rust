pub use super::internal_transfer::AddressPocket;
use crate::{
    executive::FrameReturn,
    vm::{ActionParams, Result as VmResult},
};

use impl_tools::autoimpl;
use impl_trait_for_tuples::impl_for_tuples;

#[impl_for_tuples(3)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
pub trait CheckpointTracer {
    fn trace_checkpoint(&mut self) {}

    /// Discard the top checkpoint for validity mark
    fn trace_checkpoint_discard(&mut self) {}

    /// Mark the traces to the top checkpoint as "valid = false"
    fn trace_checkpoint_revert(&mut self) {}
}

#[impl_for_tuples(3)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
#[allow(unused_variables)]
pub trait CallTracer {
    /// Prepares call trace for given params.
    fn record_call(&mut self, params: &ActionParams) {}

    /// Prepares call result trace
    fn record_call_result(&mut self, result: &VmResult<FrameReturn>) {}

    /// Prepares create trace for given params.
    fn record_create(&mut self, params: &ActionParams) {}

    /// Prepares create result trace
    fn record_create_result(&mut self, result: &VmResult<FrameReturn>) {}
}
