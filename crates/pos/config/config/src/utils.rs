// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_types::{
    account_address::AccountAddress,
    transaction::authenticator::AuthenticationKey,
};

pub fn default_validator_owner_auth_key_from_name(
    name: &[u8],
) -> AuthenticationKey {
    let salt = "validator_owner::";
    let mut name_in_bytes = salt.as_bytes().to_vec();
    name_in_bytes.extend_from_slice(name);
    let hash = diem_crypto::HashValue::sha3_256_of(&name_in_bytes);
    AuthenticationKey::new(*hash.as_ref())
}

pub fn validator_owner_account_from_name(name: &[u8]) -> AccountAddress {
    default_validator_owner_auth_key_from_name(name).derived_address()
}
