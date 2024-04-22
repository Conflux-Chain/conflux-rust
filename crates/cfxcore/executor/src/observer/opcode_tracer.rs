use impl_tools::autoimpl;
use impl_trait_for_tuples::impl_for_tuples;

#[impl_for_tuples(3)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
pub trait OpcodeTracer {
    fn do_trace_opcode(&self, _enabled: &mut bool) {}
    // TODO[geth-tracer]: Define your hook here for EVM opcode
}
