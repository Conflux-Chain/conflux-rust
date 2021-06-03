// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common::Author, sync_info::SyncInfo, vote::Vote};
use anyhow::ensure;
use diem_crypto::HashValue;
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
use diem_types::{
    block_info::PivotBlockDecision, validator_config::ConsensusSignature,
    validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// VoteMsg is the struct that is ultimately sent by the voter in response for
/// receiving a proposal.
/// VoteMsg carries the `LedgerInfo` of a block that is going to be committed in
/// case this vote is gathers QuorumCertificate (see the detailed explanation in
/// the comments of `LedgerInfo`).
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct PivotDecisionMsg {
    pivot_decision: PivotBlockDecision,
    author: Author,
    signature: ConsensusSignature,
}

impl Display for PivotDecisionMsg {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "PivotDecisionMsg: [{}]", self.pivot_decision.block_hash,)
    }
}

impl PivotDecisionMsg {
    pub fn new(
        pivot_decision: PivotBlockDecision, validator_signer: &ValidatorSigner,
    ) -> Self {
        let signature = validator_signer.sign(&pivot_decision);
        Self {
            pivot_decision,
            author: validator_signer.author(),
            signature,
        }
    }

    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        validator.verify(self.author, &self.pivot_decision, &self.signature)?;
        Ok(())
    }
}
