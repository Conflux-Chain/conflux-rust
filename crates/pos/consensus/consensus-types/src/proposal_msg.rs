// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{block::Block, common::Author, sync_info::SyncInfo};
use anyhow::{anyhow, ensure, format_err, Context, Result};
use diem_types::validator_verifier::ValidatorVerifier;
use serde::{Deserialize, Serialize};
use std::fmt;

/// ProposalMsg contains the required information for the proposer election
/// protocol to make its choice (typically depends on round and proposer info).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposalMsg {
    proposal: Block,
    sync_info: SyncInfo,
}

impl ProposalMsg {
    /// Creates a new proposal.
    pub fn new(proposal: Block, sync_info: SyncInfo) -> Self {
        Self {
            proposal,
            sync_info,
        }
    }

    pub fn epoch(&self) -> u64 { self.proposal.epoch() }

    /// Verifies that the ProposalMsg is well-formed.
    pub fn verify_well_formed(&self) -> Result<()> {
        ensure!(
            !self.proposal.is_nil_block(),
            "Proposal {} for a NIL block",
            self.proposal
        );
        self.proposal
            .verify_well_formed()
            .context("Fail to verify ProposalMsg's block")?;
        ensure!(
            self.proposal.round() > 0,
            "Proposal for {} has an incorrect round of 0",
            self.proposal,
        );
        ensure!(
            self.proposal.epoch() == self.sync_info.epoch(),
            "ProposalMsg has different epoch number from SyncInfo"
        );
        ensure!(
            self.proposal.parent_id()
                == self.sync_info.highest_quorum_cert().certified_block().id(),
            "Proposal HQC in SyncInfo certifies {}, but block parent id is {}",
            self.sync_info.highest_quorum_cert().certified_block().id(),
            self.proposal.parent_id(),
        );
        let previous_round = self
            .proposal
            .round()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("proposal round overflowed!"))?;

        let highest_certified_round = std::cmp::max(
            self.proposal.quorum_cert().certified_block().round(),
            self.sync_info
                .highest_timeout_certificate()
                .map_or(0, |tc| tc.round()),
        );
        ensure!(
            previous_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.proposal,
            previous_round
        );
        ensure!(
            self.proposal.author().is_some(),
            "Proposal {} does not define an author",
            self.proposal
        );
        Ok(())
    }

    pub fn verify(
        &self, validator: &ValidatorVerifier, epoch_vrf_seed: &[u8],
    ) -> Result<()> {
        // Run well-formedness first: it rejects NilBlock/Genesis and
        // guarantees `author().is_some()` for the VRF branch below.
        self.verify_well_formed()?;
        self.proposal
            .validate_signature(validator)
            .map_err(|e| format_err!("{:?}", e))?;

        if let Some(vrf_proof) = self.proposal.vrf_proof() {
            let author = self.proposal.author().ok_or_else(|| {
                format_err!("VRF proof present but block has no author")
            })?;
            validator.verify_vrf(
                author,
                &self.proposal.block_data().vrf_round_seed(epoch_vrf_seed),
                vrf_proof,
            )?;
        }
        if let Some(tc) = self.sync_info.highest_timeout_certificate() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
        Ok(())
    }

    pub fn proposal(&self) -> &Block { &self.proposal }

    pub fn take_proposal(self) -> Block { self.proposal }

    pub fn sync_info(&self) -> &SyncInfo { &self.sync_info }

    /// `None` for `NilBlock` / `Genesis`. Peer messages may carry either
    /// before validation, so we don't panic here.
    pub fn proposer(&self) -> Option<Author> { self.proposal.author() }
}

impl fmt::Display for ProposalMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[proposal {} from ", self.proposal)?;
        match self.proposal.author() {
            Some(author) => write!(f, "{}]", hex::encode(&author[..4])),
            None => write!(f, "NIL]"),
        }
    }
}
