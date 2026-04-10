// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! AccessPath represents a key into global storage. It is used as the
//! key type in WriteSet entries.
//!
//! This module is kept for BCS deserialization compatibility with
//! existing PoS ledger DB data (genesis transaction at version 0).

use crate::account_address::AccountAddress;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct AccessPath {
    pub address: AccountAddress,
    #[serde(with = "serde_bytes")]
    pub path: Vec<u8>,
}

impl AccessPath {
    pub fn new(address: AccountAddress, path: Vec<u8>) -> Self {
        AccessPath { address, path }
    }
}

impl fmt::Debug for AccessPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccessPath {{ address: {:x}, path: {} }}",
            self.address,
            hex::encode(&self.path)
        )
    }
}

impl fmt::Display for AccessPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
