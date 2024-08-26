use rlp_derive::{RlpDecodable, RlpEncodable};
use space::Space;

#[derive(
    Default, Copy, Clone, Debug, Eq, PartialEq, RlpEncodable, RlpDecodable,
)]
pub struct AllChainID {
    native: u32,
    ethereum: u32,
}

impl AllChainID {
    pub fn new(native: u32, ethereum: u32) -> Self { Self { native, ethereum } }

    pub fn fake_for_virtual(chain_id: u32) -> Self {
        Self {
            native: chain_id,
            ethereum: chain_id,
        }
    }

    pub fn in_space(&self, space: Space) -> u32 {
        match space {
            Space::Native => self.native,
            Space::Ethereum => self.ethereum,
        }
    }

    pub fn in_native_space(&self) -> u32 { self.in_space(Space::Native) }

    pub fn in_evm_space(&self) -> u32 { self.in_space(Space::Ethereum) }
}
