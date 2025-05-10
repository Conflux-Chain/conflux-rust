use cfx_types::H256;
use solidity_abi::{ABIEncodable, EventIndexEncodable};

use cfx_vm_types::{self as vm, ActionParams};

use super::context::InternalRefContext;

/// Native implementation of a solidity-interface function.
pub trait SolidityEventTrait: Send + Sync {
    type Indexed: EventIndexEncodable;
    type NonIndexed: ABIEncodable;
    const EVENT_SIG: H256;

    fn log(
        indexed: &Self::Indexed, non_indexed: &Self::NonIndexed,
        param: &ActionParams, context: &mut InternalRefContext,
    ) -> vm::Result<()> {
        let mut topics = vec![Self::EVENT_SIG];
        topics.extend_from_slice(&indexed.indexed_event_encode());

        let data = non_indexed.abi_encode();

        context.log(param, context.spec, topics, data)
    }
}

#[macro_export]
macro_rules! make_solidity_event {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($interface:expr $(, indexed: $indexed:ty)? $(, non_indexed: $non_indexed:ty)?); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name;

        impl SolidityEventTrait for $name {
            $(type Indexed = $indexed;)?
            $(type NonIndexed = $non_indexed;)?
            const EVENT_SIG: H256 = H256(keccak!($interface));
        }
    };
}
