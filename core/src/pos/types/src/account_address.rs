// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use crate::transaction::authenticator::AuthenticationKey;
use diem_crypto::{
    ed25519::Ed25519PublicKey,
    hash::{CryptoHasher, HashValue},
    x25519, ValidCryptoMaterial,
};

use crate::validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey};
use cfx_types::H256;
pub use move_core_types::account_address::AccountAddress;
use tiny_keccak::{Hasher, Keccak};

pub fn from_public_key(public_key: &Ed25519PublicKey) -> AccountAddress {
    AuthenticationKey::ed25519(public_key).derived_address()
}

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

// Note: This is inconsistent with current types because AccountAddress is
// derived from consensus key which is of type Ed25519PublicKey. Since
// AccountAddress does not mean anything in a setting without remote
// authentication, we use the network public key to generate a peer_id for the
// peer. See this issue for potential improvements: https://github.com/diem/diem/issues/3960
pub fn from_identity_public_key(
    identity_public_key: x25519::PublicKey,
) -> AccountAddress {
    let mut array = [0u8; AccountAddress::LENGTH];
    let pubkey_slice = identity_public_key.as_slice();
    // keep only the last 16 bytes
    array.copy_from_slice(
        &pubkey_slice[x25519::PUBLIC_KEY_SIZE - AccountAddress::LENGTH..],
    );
    AccountAddress::new(array)
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
