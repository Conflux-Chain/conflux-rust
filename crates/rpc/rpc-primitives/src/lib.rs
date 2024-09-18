mod bytes;
mod index;
mod variadic_u64;
mod variadic_value;
mod rpc_module;

pub use bytes::Bytes;
pub use index::Index;
pub use variadic_u64::U64;
pub use variadic_value::VariadicValue;
pub use rpc_module::RpcModules;

// helper implementing automatic Option<Vec<A>> -> Option<Vec<B>> conversion
pub fn maybe_vec_into<A, B>(src: &Option<Vec<A>>) -> Option<Vec<B>>
where A: Clone + Into<B> {
    src.clone().map(|x| x.into_iter().map(Into::into).collect())
}
