use crate::evm::Spec;
pub use primitives::BlockNumber;

pub trait ActivateAtTrait {
    fn activate_at(&self, block_number: BlockNumber, spec: &Spec) -> bool;
}

#[macro_export]
macro_rules! impl_activate_at {
    ($name:ident,"genesis") => {
        impl ActivateAtTrait for $name {
            fn activate_at(&self, _: BlockNumber, _: &Spec) -> bool { true }
        }
    };
    ($name:ident,"21Q2-hardfork") => {
        impl ActivateAtTrait for $name {
            fn activate_at(&self, _: BlockNumber, _: &Spec) -> bool { false }
        }
    };
}

#[macro_export]
macro_rules! group_impl_activate_at {
    ($desc:tt $(, $name:ident)* $(,)?) => {
        $(impl_activate_at!($name, $desc);)*
    };
}
