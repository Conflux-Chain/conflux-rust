use ethereum_types::Address;
use space::Space;

#[derive(Default, Eq, PartialEq, Hash, Copy, Clone, Debug, Ord, PartialOrd)]
pub struct AddressWithSpace {
    pub address: Address,
    pub space: Space,
}

impl AddressWithSpace {
    #[inline]
    pub fn assert_native(&self) { assert_eq!(self.space, Space::Native) }
}
