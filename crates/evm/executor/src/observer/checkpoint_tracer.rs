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
