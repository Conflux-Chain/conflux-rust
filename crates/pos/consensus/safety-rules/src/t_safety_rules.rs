// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{ConsensusState, Error};
use consensus_types::{
    block::Block, block_data::BlockData, timeout::Timeout, vote::Vote,
    vote_proposal::MaybeSignedVoteProposal,
};
use diem_types::{
    epoch_state::EpochState, validator_config::ConsensusSignature,
};

/// Interface for SafetyRules
pub trait TSafetyRules {
    /// Provides the internal state of SafetyRules for monitoring / debugging
    /// purposes. This does not include sensitive data like private keys.
    fn consensus_state(&mut self) -> Result<ConsensusState, Error>;

    /// Initialize SafetyRules with the given epoch state. Sets up the
    /// validator set and signing keys for the epoch.
    fn initialize(&mut self, epoch_state: &EpochState) -> Result<(), Error>;

    /// Attempts to vote for a given proposal following the voting rules.
    fn construct_and_sign_vote(
        &mut self, vote_proposal: &MaybeSignedVoteProposal,
    ) -> Result<Vote, Error>;

    /// As the holder of the private key, SafetyRules also signs proposals or
    /// blocks. A Block is a signed BlockData along with some additional
    /// metadata.
    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error>;

    /// As the holder of the private key, SafetyRules also signs what is
    /// effectively a timeout message. This returns the signature for that
    /// timeout message.
    fn sign_timeout(
        &mut self, timeout: &Timeout,
    ) -> Result<ConsensusSignature, Error>;

    /// Allow the safety rule to start voting with saved secure data from
    /// another node.
    fn start_voting(&mut self, _initialize: bool) -> Result<(), Error> {
        Err(Error::SecureStorageUnexpectedError(
            "unsupported safety rule type".to_string(),
        ))
    }

    /// Stop the safety rule from voting and save secure data.
    fn stop_voting(&mut self) -> Result<(), Error> {
        Err(Error::SecureStorageUnexpectedError(
            "unsupported safety rule type".to_string(),
        ))
    }
}
