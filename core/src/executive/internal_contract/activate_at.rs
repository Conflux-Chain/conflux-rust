use crate::evm::Spec;
pub use primitives::BlockNumber;

pub trait IsActive {
    fn is_active(&self, spec: &Spec) -> bool;
}

#[macro_export]
macro_rules! group_impl_is_active {
    ("genesis" $(, $name:ident)* $(,)?) => {
        group_impl_is_active!(|_| true $(, $name)*);
    };
    ($is_active:expr $(, $name:ident)* $(,)?) => {
        $(impl IsActive for $name {
            fn is_active(&self, spec: &Spec) -> bool { $is_active(spec) }
        })*
    };
}
