use super::{Address, AddressWithSpace, Space};

pub trait AddressSpaceUtil: Sized {
    fn with_space(self, space: Space) -> AddressWithSpace;
    fn with_native_space(self) -> AddressWithSpace {
        self.with_space(Space::Native)
    }
    fn with_evm_space(self) -> AddressWithSpace {
        self.with_space(Space::Ethereum)
    }
}

impl AddressSpaceUtil for Address {
    fn with_space(self, space: Space) -> AddressWithSpace {
        AddressWithSpace {
            address: self,
            space,
        }
    }
}
