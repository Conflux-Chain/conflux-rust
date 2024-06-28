// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::block::Block;
use diem_crypto::hash::TransactionAccumulatorHasher;
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
use diem_types::{
    block_info::PivotBlockDecision, epoch_state::EpochState,
    proof::AccumulatorExtensionProof, validator_config::ConsensusSignature,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    ops::Deref,
};

/// This structure contains all the information needed by safety rules to
/// evaluate a proposal / block for correctness / safety and to produce a Vote.
#[derive(Clone, Debug, CryptoHasher, Deserialize, BCSCryptoHash, Serialize)]
pub struct VoteProposal {
    /// Contains the data necessary to construct the parent's execution output
    /// state and the childs in a verifiable way
    accumulator_extension_proof:
        AccumulatorExtensionProof<TransactionAccumulatorHasher>,
    /// The block / proposal to evaluate
    #[serde(bound(deserialize = "Block: Deserialize<'de>"))]
    block: Block,
    /// An optional field containing the next epoch info.
    next_epoch_state: Option<EpochState>,
    /// The pivot decision after `block` is executed.
    pivot_decision: Option<PivotBlockDecision>,
}

impl VoteProposal {
    pub fn new(
        accumulator_extension_proof: AccumulatorExtensionProof<
            TransactionAccumulatorHasher,
        >,
        block: Block, next_epoch_state: Option<EpochState>,
        pivot_decision: Option<PivotBlockDecision>,
    ) -> Self {
        Self {
            accumulator_extension_proof,
            block,
            next_epoch_state,
            pivot_decision,
        }
    }

    pub fn accumulator_extension_proof(
        &self,
    ) -> &AccumulatorExtensionProof<TransactionAccumulatorHasher> {
        &self.accumulator_extension_proof
    }

    pub fn block(&self) -> &Block { &self.block }

    pub fn next_epoch_state(&self) -> Option<&EpochState> {
        self.next_epoch_state.as_ref()
    }

    pub fn pivot_decision(&self) -> &Option<PivotBlockDecision> {
        &self.pivot_decision
    }
}

impl Display for VoteProposal {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "VoteProposal[block: {}]", self.block,)
    }
}

/// Wraps a vote_proposal and its signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MaybeSignedVoteProposal {
    /// The vote proposal to be signed.
    pub vote_proposal: VoteProposal,

    /// The signature of this proposal's hash from Diem Execution Correctness
    /// service. It is an `Option` because the LEC can be configured to not
    /// sign the vote hash.
    pub signature: Option<ConsensusSignature>,
}

impl Deref for MaybeSignedVoteProposal {
    type Target = VoteProposal;

    fn deref(&self) -> &VoteProposal { &self.vote_proposal }
}
