// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_config, on_chain_config::OnChainConfig,
    validator_info::ValidatorInfo,
};
use anyhow::Result;

use crate::event::EventKey;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::{fmt, iter::IntoIterator, vec};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[repr(u8)]
pub enum ConsensusScheme {
    Ed25519 = 0,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ValidatorSet {
    scheme: ConsensusScheme,
    payload: Vec<ValidatorInfo>,
}

impl fmt::Display for ValidatorSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for validator in self.payload().iter() {
            write!(f, "{} ", validator)?;
        }
        write!(f, "]")
    }
}

impl ValidatorSet {
    /// Constructs a ValidatorSet resource.
    pub fn new(payload: Vec<ValidatorInfo>) -> Self {
        Self {
            scheme: ConsensusScheme::Ed25519,
            payload,
        }
    }

    pub fn payload(&self) -> &[ValidatorInfo] { &self.payload }

    pub fn empty() -> Self { ValidatorSet::new(Vec::new()) }

    pub fn change_event_key() -> EventKey {
        EventKey::new_from_address(&account_config::validator_set_address(), 2)
    }
}

impl OnChainConfig for ValidatorSet {
    // validator_set_address
    const IDENTIFIER: &'static str = "DiemSystem";
}

impl IntoIterator for ValidatorSet {
    type IntoIter = vec::IntoIter<Self::Item>;
    type Item = ValidatorInfo;

    fn into_iter(self) -> Self::IntoIter { self.payload.into_iter() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextValidatorSetProposal {
    pub this_membership_id: u64,
    pub next_validator_set: ValidatorSet,
}

impl NextValidatorSetProposal {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}
