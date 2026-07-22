use impl_tools::autoimpl;
use impl_trait_for_tuples::impl_for_tuples;

#[impl_for_tuples(4)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
pub trait StorageTracer {}
