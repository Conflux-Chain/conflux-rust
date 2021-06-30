use crate::evm::Spec;
pub use primitives::BlockNumber;

pub trait IsActive {
    fn is_active(&self, spec: &Spec) -> bool;
}

#[macro_export]
macro_rules! impl_activate_at {
    ($name:ident,"genesis") => {
        impl IsActive for $name {
            fn is_active(&self, _: &Spec) -> bool { true }
        }
    };
}

#[macro_export]
macro_rules! group_impl_activate_at {
    ($desc:tt $(, $name:ident)* $(,)?) => {
        $(impl_activate_at!($name, $desc);)*
    };
}
