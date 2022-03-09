// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{ConsensusState, Error, SafetyRules, TSafetyRules};
use consensus_types::{
    block::Block, block_data::BlockData, timeout::Timeout, vote::Vote,
    vote_proposal::MaybeSignedVoteProposal,
};
use diem_infallible::RwLock;
use diem_types::{
    epoch_change::EpochChangeProof, validator_config::ConsensusSignature,
};
use std::sync::Arc;

/// A local interface into SafetyRules. Constructed in such a way that the
/// container / caller cannot distinguish this API from an actual client/server
/// process without being exposed to the actual container instead the caller can
/// access a Box<dyn TSafetyRules>.
pub struct LocalClient {
    internal: Arc<RwLock<SafetyRules>>,
}

impl LocalClient {
    pub fn new(internal: Arc<RwLock<SafetyRules>>) -> Self { Self { internal } }
}

impl TSafetyRules for LocalClient {
    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        self.internal.write().consensus_state()
    }

    fn initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        self.internal.write().initialize(proof)
    }

    fn construct_and_sign_vote(
        &mut self, vote_proposal: &MaybeSignedVoteProposal,
    ) -> Result<Vote, Error> {
        self.internal.write().construct_and_sign_vote(vote_proposal)
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        self.internal.write().sign_proposal(block_data)
    }

    fn sign_timeout(
        &mut self, timeout: &Timeout,
    ) -> Result<ConsensusSignature, Error> {
        self.internal.write().sign_timeout(timeout)
    }

    fn start_voting(&mut self, initialize: bool) -> Result<(), Error> {
        self.internal.write().start_voting(initialize)
    }

    fn stop_voting(&mut self) -> Result<(), Error> {
        self.internal.write().stop_voting()
    }
}
