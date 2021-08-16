// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::{Author, Round},
    timeout::Timeout,
};
use anyhow::Context;
use diem_types::{
    validator_config::ConsensusSignature, validator_verifier::ValidatorVerifier,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
/// TimeoutCertificate is a proof that 2f+1 participants in epoch i
/// have voted in round r and we can now move to round r+1.
pub struct TimeoutCertificate {
    timeout: Timeout,
    signatures: BTreeMap<Author, ConsensusSignature>,
}

impl fmt::Display for TimeoutCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TimeoutCertificate[epoch: {}, round: {}]",
            self.timeout.epoch(),
            self.timeout.round(),
        )
    }
}

impl TimeoutCertificate {
    /// Creates new TimeoutCertificate
    pub fn new(timeout: Timeout) -> Self {
        Self {
            timeout,
            signatures: BTreeMap::new(),
        }
    }

    /// Verifies the signatures for the round
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        validator
            .verify_aggregated_struct_signature(&self.timeout, &self.signatures)
            .context("Failed to verify TimeoutCertificate")?;
        Ok(())
    }

    /// Returns the epoch of the timeout certificate
    pub fn epoch(&self) -> u64 { self.timeout.epoch() }

    /// Returns the round of the timeout certificate
    pub fn round(&self) -> Round { self.timeout.round() }

    /// Returns the signatures certifying the round
    pub fn signatures(&self) -> &BTreeMap<Author, ConsensusSignature> {
        &self.signatures
    }

    pub fn add_signature(
        &mut self, author: Author, signature: ConsensusSignature,
    ) {
        self.signatures.entry(author).or_insert(signature);
    }

    pub fn remove_signature(&mut self, author: Author) {
        self.signatures.remove(&author);
    }
}
