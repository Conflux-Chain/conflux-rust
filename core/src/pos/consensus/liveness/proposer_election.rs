// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use consensus_types::{
    block::Block,
    block_data::BlockData,
    common::{Author, Round},
};
use diem_types::validator_config::ConsensusVRFProof;
use fallible::copy_from_slice::copy_slice_to_vec;

/// ProposerElection incorporates the logic of choosing a leader among multiple
/// candidates. We are open to a possibility for having multiple proposers per
/// round, the ultimate choice of a proposal is exposed by the election protocol
/// via the stream of proposals.
pub trait ProposerElection {
    /// If a given author is a valid candidate for being a proposer, generate
    /// the info, otherwise return None.
    /// Note that this function is synchronous.
    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        self.get_valid_proposer(round) == author
    }

    /// Return the valid proposer for a given round (this information can be
    /// used by e.g., voters for choosing the destinations for sending their
    /// votes to).
    fn get_valid_proposer(&self, round: Round) -> Author;

    /// Return if a given proposed block is valid.
    fn is_valid_proposal(&self, block: &Block) -> bool {
        block.author().map_or(false, |author| {
            self.is_valid_proposer(author, block.round())
        })
    }

    /// TODO(lpl): Find a better way to integrate VRF and deterministic leader
    /// election. Return `true` if we use random leader election, which
    /// means we can only choose proposal candidates to vote after waiting
    /// for a fixed period of time, and `get_valid_proposer` returns meaningless
    /// value.
    fn is_random_election(&self) -> bool { false }

    fn receive_proposal_candidate(
        &self, _block: Block,
    ) -> anyhow::Result<bool> {
        unreachable!()
    }

    /// Choose a proposal from all received proposal candidates to vote for.
    fn choose_proposal_to_vote(&self) -> Option<Block> { unreachable!() }

    fn next_round(&self, _round: Round, _new_seed: Vec<u8>) { unreachable!() }

    fn gen_vrf_proof(
        &self, _block_data: &BlockData,
    ) -> Option<ConsensusVRFProof> {
        unreachable!()
    }
}

// next continuously mutates a state and returns a u64-index
pub(crate) fn next(state: &mut Vec<u8>) -> u64 {
    // state = SHA-3-256(state)
    *state = diem_crypto::HashValue::sha3_256_of(state).to_vec();
    let mut temp = [0u8; 8];
    copy_slice_to_vec(&state[..8], &mut temp).expect("next failed");
    // return state[0..8]
    u64::from_le_bytes(temp)
}
