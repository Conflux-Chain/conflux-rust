// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate ethereum_types;
extern crate keccak_hash;
extern crate rlp;
extern crate rlp_derive;
extern crate serde;
extern crate serde_derive;

pub use ethereum_types::{
    Address, BigEndianHash, Bloom, BloomInput, Public, Secret, Signature, H128,
    H160, H256, H512, H520, H64, U128, U256, U512, U64,
};

mod space;
pub use space::{Space, SpaceMap};

mod all_chainid;
pub use all_chainid::AllChainID;

mod address_with_space;
pub use address_with_space::AddressWithSpace;

mod utils;
pub use utils::*;

pub mod address_util;

pub mod space_util;
pub use space_util::AddressSpaceUtil;

pub mod contract_address;
pub use contract_address::{cal_contract_address, CreateContractAddressType};

/// The KECCAK hash of an empty bloom filter (0x00 * 256)
pub const KECCAK_EMPTY_BLOOM: H256 = H256([
    0xd3, 0x97, 0xb3, 0xb0, 0x43, 0xd8, 0x7f, 0xcd, 0x6f, 0xad, 0x12, 0x91,
    0xff, 0x0b, 0xfd, 0x16, 0x40, 0x1c, 0x27, 0x48, 0x96, 0xd8, 0xc6, 0x3a,
    0x92, 0x37, 0x27, 0xf0, 0x77, 0xb8, 0xe0, 0xb5,
]);
