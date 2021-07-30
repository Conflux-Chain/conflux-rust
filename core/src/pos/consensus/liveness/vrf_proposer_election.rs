// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::pos::consensus::liveness::proposer_election::ProposerElection;
use consensus_types::common::{Author, Round};

use cfx_types::U256;
use consensus_types::{block::Block, block_data::BlockData};
use diem_crypto::{VRFPrivateKey, VRFProof};
use diem_logger::debug as diem_debug;
use diem_types::{
    account_address::AccountAddress,
    epoch_state::EpochState,
    validator_config::{ConsensusVRFPrivateKey, ConsensusVRFProof},
};
use parking_lot::Mutex;
use std::collections::HashMap;

/// The round proposer maps a round to author
pub struct VrfProposer {
    author: Author,
    vrf_private_key: ConsensusVRFPrivateKey,

    proposal_threshold: U256,

    current_round: Mutex<Round>,
    current_seed: Mutex<Vec<u8>>,
    proposal_candidates: Mutex<HashMap<AccountAddress, Block>>,

    // The epoch state of `current_round`, used to verify proposals.
    epoch_state: EpochState,
}

impl VrfProposer {
    pub fn new(
        author: Author, vrf_private_key: ConsensusVRFPrivateKey,
        proposal_threshold: U256, epoch_state: EpochState,
    ) -> Self
    {
        Self {
            author,
            vrf_private_key,
            proposal_threshold,
            // current_round and current_seed will not be used before
            // `next_round` is called.
            current_round: Mutex::new(0),
            current_seed: Mutex::new(vec![]),
            proposal_candidates: Default::default(),
            epoch_state,
        }
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
        // TODO(lpl): Unify seed computation.
        let mut round_seed = self.current_seed.lock().clone();
        round_seed.extend_from_slice(&round.to_be_bytes());
        let vrf_output = self
            .vrf_private_key
            .compute(round_seed.as_slice())
            .unwrap()
            .to_hash()
            .unwrap();
        let vrf_number = U256::from_big_endian(vrf_output.as_ref());
        vrf_number <= self.proposal_threshold
    }

    fn is_valid_proposal(&self, block: &Block) -> bool {
        let mut round_seed = self.current_seed.lock().clone();
        round_seed.extend_from_slice(&block.round().to_be_bytes());
        let vrf_hash = match self
            .epoch_state
            .verifier
            .get_vrf_public_key(&block.author().expect("proposals have author"))
        {
            Some(Some(vrf_public_key)) => {
                match block
                    .vrf_proof()
                    .unwrap()
                    .verify(round_seed.as_slice(), &vrf_public_key)
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
        // FIXME(lpl): Verify VRF.
        let vrf_number = vrf_hash.to_u256();
        vrf_number <= self.proposal_threshold
    }

    fn is_random_election(&self) -> bool { true }

    /// Return `Err` for invalid or unmatching blocks.
    /// Return `Ok(true)` if the block is valid and received for the first time.
    /// Return `Ok(false)` if the block was received before.
    fn receive_proposal_candidate(&self, block: Block) -> anyhow::Result<bool> {
        if !self.is_valid_proposal(&block) {
            anyhow::bail!("Invalid proposal");
        }
        if block.round() != *self.current_round.lock() {
            anyhow::bail!("Incorrect round");
        }
        Ok(self
            .proposal_candidates
            .lock()
            .insert(block.author().unwrap(), block)
            .is_none())
    }

    /// Choose a proposal from all received proposal candidates to vote for.
    fn choose_proposal_to_vote(&self) -> Option<Block> {
        let mut chosen_proposal = None;
        let mut min_vrf_number = U256::MAX;
        for (_, b) in &*self.proposal_candidates.lock() {
            let vrf_number =
                b.vrf_proof().unwrap().to_hash().unwrap().to_u256();
            if vrf_number < min_vrf_number {
                chosen_proposal = Some(b.clone());
                min_vrf_number = vrf_number
            }
        }
        diem_debug!("choose_proposal_to_vote: {:?}", chosen_proposal);
        chosen_proposal
    }

    fn next_round(&self, round: Round, new_seed: Vec<u8>) {
        *self.current_round.lock() = round;
        self.proposal_candidates.lock().clear();
        *self.current_seed.lock() = new_seed;
    }

    fn gen_vrf_proof(
        &self, block_data: &BlockData,
    ) -> Option<ConsensusVRFProof> {
        self.vrf_private_key
            .compute(
                block_data
                    .vrf_round_seed(self.current_seed.lock().as_slice())
                    .as_slice(),
            )
            .ok()
    }
}
