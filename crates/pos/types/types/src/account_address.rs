// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use diem_crypto::{
    hash::{CryptoHasher, HashValue},
    ValidCryptoMaterial,
};

use crate::validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey};
use cfx_types::H256;
pub use move_core_types::account_address::AccountAddress;
use tiny_keccak::{Hasher, Keccak};

pub fn from_consensus_public_key(
    public_key: &ConsensusPublicKey, vrf_public_key: &ConsensusVRFPublicKey,
) -> AccountAddress {
    let mut hasher = Keccak::v256();
    hasher.update(public_key.to_bytes().as_slice());
    hasher.update(vrf_public_key.to_bytes().as_slice());
    let mut h = H256::default();
    hasher.finalize(h.as_bytes_mut());
    AccountAddress::new(h.0)
}

// Define the Hasher used for hashing AccountAddress types. In order to properly
// use the CryptoHasher derive macro we need to have this in its own module so
// that it doesn't conflict with the imported `AccountAddress` from
// move-core-types. It needs to have the same name since the hash salt is
// calculated using the name of the type.
mod hasher {
    #[derive(serde::Deserialize, diem_crypto_derive::CryptoHasher)]
    struct AccountAddress;
}

pub trait HashAccountAddress {
    fn hash(&self) -> HashValue;
}

impl HashAccountAddress for AccountAddress {
    fn hash(&self) -> HashValue {
        let mut state = hasher::AccountAddressHasher::default();
        state.update(self.as_ref());
        state.finish()
    }
}

#[cfg(test)]
mod test {
    use super::{AccountAddress, HashAccountAddress};
    use diem_crypto::hash::HashValue;
    use hex::FromHex;

    #[test]
    fn address_hash() {
        let address: AccountAddress =
            "ca843279e3427144cead5e4d5999a3d0ca843279e3427144cead5e4d5999a3d0"
                .parse()
                .unwrap();

        let hash_vec = &Vec::from_hex(
            "81fdf1b3fe04abd62ada9adc8852fab3d1b145b875c259f017e697ea2f4da249",
        )
        .expect("You must provide a valid Hex format");

        let mut hash = [0u8; 32];
        let bytes = &hash_vec[..32];
        hash.copy_from_slice(&bytes);

        assert_eq!(address.hash(), HashValue::new(hash));
    }
}
