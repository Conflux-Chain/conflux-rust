// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::consensus::liveness::proposer_election::ProposerElection;
use consensus_types::common::{Author, Round};

use cfx_types::U256;
use consensus_types::{block::Block, block_data::BlockData};
use diem_crypto::{vrf_number_with_nonce, HashValue, VRFPrivateKey, VRFProof};
use diem_logger::debug as diem_debug;
use diem_types::{
    epoch_state::EpochState,
    validator_config::{ConsensusVRFPrivateKey, ConsensusVRFProof},
};
use parking_lot::Mutex;

/// The round proposer maps a round to author
pub struct VrfProposer {
    author: Author,
    vrf_private_key: ConsensusVRFPrivateKey,

    proposal_threshold: HashValue,

    current_round: Mutex<Round>,
    current_seed: Mutex<Vec<u8>>,
    proposal_candidates: Mutex<Option<Block>>,

    // The epoch state of `current_round`, used to verify proposals.
    epoch_state: EpochState,
}

impl VrfProposer {
    pub fn new(
        author: Author, vrf_private_key: ConsensusVRFPrivateKey,
        proposal_threshold_u256: U256, epoch_state: EpochState,
    ) -> Self {
        let mut proposal_threshold = [0 as u8; HashValue::LENGTH];
        proposal_threshold_u256.to_big_endian(&mut proposal_threshold);
        Self {
            author,
            vrf_private_key,
            proposal_threshold: HashValue::new(proposal_threshold),
            // current_round and current_seed will not be used before
            // `next_round` is called.
            current_round: Mutex::new(0),
            current_seed: Mutex::new(vec![]),
            proposal_candidates: Default::default(),
            epoch_state,
        }
    }

    pub fn get_vrf_number(&self, block: &Block) -> Option<HashValue> {
        Some(vrf_number_with_nonce(
            &block.vrf_proof()?.to_hash().ok()?,
            block.vrf_nonce()?,
        ))
    }
}

impl ProposerElection for VrfProposer {
    fn get_valid_proposer(&self, _round: Round) -> Author {
        unreachable!(
            "We will never get valid proposer based on round for VRF election"
        )
    }

    fn is_valid_proposer(&self, author: Author, round: Round) -> bool {
        assert_eq!(
            author, self.author,
            "VRF election can not check proposer validity without vrf_proof"
        );
        assert_eq!(
            round,
            *self.current_round.lock(),
            "VRF election can not generate vrf_proof for other rounds"
        );
        let voting_power =
            match self.epoch_state.verifier().get_voting_power(&author) {
                None => return false,
                Some(p) => p,
            };
        // TODO(lpl): Unify seed computation and avoid duplicate computation
        // with `gen_vrf_nonce_and_proof`.
        let mut round_seed = self.current_seed.lock().clone();
        let leader_round = (round + 1) / 3;
        round_seed.extend_from_slice(&leader_round.to_be_bytes());
        let vrf_output = self
            .vrf_private_key
            .compute(round_seed.as_slice())
            .expect("vrf compute fail")
            .to_hash()
            .expect("to hash error");
        for nonce in 0..=voting_power {
            let vrf_number = vrf_number_with_nonce(&vrf_output, nonce);
            if vrf_number <= self.proposal_threshold {
                return true;
            }
        }
        false
    }

    fn is_valid_proposal(&self, block: &Block) -> bool {
        let voting_power = match self
            .epoch_state
            .verifier()
            .get_voting_power(&block.author().expect("checked"))
        {
            None => return false,
            Some(p) => p,
        };
        let nonce = block.vrf_nonce().expect("checked");
        if nonce > voting_power || *self.current_round.lock() != block.round() {
            return false;
        }
        let seed = block
            .block_data()
            .vrf_round_seed(self.current_seed.lock().as_slice());
        let vrf_hash = match self
            .epoch_state
            .verifier()
            .get_vrf_public_key(&block.author().expect("checked"))
        {
            Some(Some(vrf_public_key)) => {
                match block
                    .vrf_proof()
                    .unwrap()
                    .verify(seed.as_slice(), &vrf_public_key)
                {
                    Ok(vrf_hash) => vrf_hash,
                    Err(e) => {
                        diem_debug!("is_valid_proposal: invalid proposal err={:?}, block={:?}", e, block);
                        return false;
                    }
                }
            }
            _ => {
                diem_debug!(
                    "Receive block from non-validator: author={:?}",
                    block.author()
                );
                return false;
            }
        };
        vrf_number_with_nonce(&vrf_hash, nonce) <= self.proposal_threshold
    }

    fn is_random_election(&self) -> bool { true }

    /// Return `Err` for unmatching blocks.
    /// Return `Ok(true)` if the block has less vrf_output.
    /// Return `Ok(false)` if the block has a higher or equal vrf_output. This
    /// block should not be relayed in this case.
    fn receive_proposal_candidate(
        &self, block: &Block,
    ) -> anyhow::Result<bool> {
        // Proposal validity should have been checked in `process_proposal`.
        let current_round = *self.current_round.lock();
        if block.round() < current_round {
            anyhow::bail!("Incorrect round");
        } else if block.round() > current_round {
            // The proposal is in the future, so it should pass
            // filter_unverified_event and proceed to trigger
            // sync_up.
            return Ok(true);
        }
        let old_proposal = self.proposal_candidates.lock();
        if old_proposal.is_none()
            || self.get_vrf_number(old_proposal.as_ref().unwrap()).unwrap()
                > self.get_vrf_number(block).unwrap()
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn set_proposal_candidate(&self, block: Block) {
        *self.proposal_candidates.lock() = Some(block);
    }

    /// Choose a proposal from all received proposal candidates to vote for.
    fn choose_proposal_to_vote(&self) -> Option<Block> {
        let chosen_proposal = self.proposal_candidates.lock().clone();
        diem_debug!(
            "choose_proposal_to_vote: {:?}, data={:?}",
            chosen_proposal,
            chosen_proposal.as_ref().map(|b| b.block_data())
        );
        chosen_proposal
    }

    fn next_round(&self, round: Round, new_seed: Vec<u8>) {
        *self.current_round.lock() = round;
        self.proposal_candidates.lock().take();
        *self.current_seed.lock() = new_seed;
    }

    fn gen_vrf_nonce_and_proof(
        &self, block_data: &BlockData,
    ) -> Option<(u64, ConsensusVRFProof)> {
        let mut min_vrf_number = self.proposal_threshold;
        let mut best_nonce = None;
        let voting_power = self
            .epoch_state
            .verifier()
            .get_voting_power(&block_data.author()?)?;

        let vrf_proof = self
            .vrf_private_key
            .compute(
                block_data
                    .vrf_round_seed(self.current_seed.lock().as_slice())
                    .as_slice(),
            )
            .ok()?;
        let vrf_output = vrf_proof.to_hash().ok()?;
        for nonce in 0..=voting_power {
            let vrf_number = vrf_number_with_nonce(&vrf_output, nonce);
            if vrf_number <= min_vrf_number {
                min_vrf_number = vrf_number;
                best_nonce = Some(nonce);
            }
        }
        best_nonce.map(|nonce| (nonce, vrf_proof))
    }
}
