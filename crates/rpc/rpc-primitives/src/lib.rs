mod bytes;
mod index;
mod rpc_module;
mod variadic_u64;
mod variadic_value;

pub use bytes::Bytes;
pub use index::Index;
pub use rpc_module::RpcModules;
pub use variadic_u64::U64;
pub use variadic_value::VariadicValue;

// helper implementing automatic Option<Vec<A>> -> Option<Vec<B>> conversion
pub fn maybe_vec_into<A, B>(src: &Option<Vec<A>>) -> Option<Vec<B>>
where A: Clone + Into<B> {
    src.clone().map(|x| x.into_iter().map(Into::into).collect())
}
