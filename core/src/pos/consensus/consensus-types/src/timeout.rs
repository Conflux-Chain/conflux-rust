// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::common::Round;
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
use diem_types::{
    validator_config::ConsensusSignature, validator_signer::ValidatorSigner,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// This structure contains all the information necessary to construct a
/// signature on the equivalent of a timeout message
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    CryptoHasher,
    BCSCryptoHash,
)]
pub struct Timeout {
    /// Epoch number corresponds to the set of validators that are active for
    /// this round.
    epoch: u64,
    /// The consensus protocol executes proposals (blocks) in rounds, which
    /// monotically increase per epoch.
    round: Round,
}

impl Timeout {
    pub fn new(epoch: u64, round: Round) -> Self { Self { epoch, round } }

    pub fn epoch(&self) -> u64 { self.epoch }

    pub fn round(&self) -> Round { self.round }

    pub fn sign(&self, signer: &ValidatorSigner) -> ConsensusSignature {
        signer.sign(self)
    }
}

impl Display for Timeout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Timeout: [epoch: {}, round: {}]", self.epoch, self.round,)
    }
}
