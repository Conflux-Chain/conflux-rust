use crate::evm::Spec;
pub use primitives::BlockNumber;

pub trait IsActive {
    fn is_active(&self, spec: &Spec) -> bool;
}

#[macro_export]
macro_rules! group_impl_activate_at {
    ("genesis" $(, $name:ident)* $(,)?) => {
        group_impl_activate_at!(|_| true $(, $name)*);
    };
    ($is_active:expr $(, $name:ident)* $(,)?) => {
        $(impl IsActive for $name {
            fn is_active(&self, spec: &Spec) -> bool { $is_active(spec) }
        })*
    };
}
