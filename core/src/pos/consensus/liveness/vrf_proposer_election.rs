// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::pos::consensus::liveness::proposer_election::ProposerElection;
use consensus_types::common::{Author, Round};

use cfx_types::U256;
use consensus_types::block::{Block, VRF_SEED};
use diem_crypto::{VRFPrivateKey, VRFProof};
use diem_logger::debug as diem_debug;
use diem_types::{
    account_address::AccountAddress, validator_config::ConsensusVRFPrivateKey,
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
}

impl VrfProposer {
    pub fn new(
        author: Author, vrf_private_key: ConsensusVRFPrivateKey,
        proposal_threshold: U256,
    ) -> Self
    {
        Self {
            author,
            vrf_private_key,
            proposal_threshold,
            current_round: Mutex::new(0),
            current_seed: Mutex::new(VRF_SEED.to_vec()),
            proposal_candidates: Default::default(),
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
        let vrf_output = self
            .vrf_private_key
            .compute(&*self.current_seed.lock())
            .unwrap()
            .to_hash()
            .unwrap();
        let vrf_number = U256::from_big_endian(vrf_output.as_ref());
        vrf_number <= self.proposal_threshold
    }

    fn is_valid_proposal(&self, block: &Block) -> bool {
        let vrf_number = U256::from_big_endian(
            block.vrf_proof().unwrap().to_hash().unwrap().as_ref(),
        );
        vrf_number <= self.proposal_threshold
    }

    fn is_random_election(&self) -> bool { true }

    fn receive_proposal_candidate(&self, block: Block) -> bool {
        if self.is_valid_proposal(&block)
            && block.round() == *self.current_round.lock()
        {
            self.proposal_candidates
                .lock()
                .insert(block.author().unwrap(), block)
                .is_none()
        } else {
            false
        }
    }

    /// Choose a proposal from all received proposal candidates to vote for.
    fn choose_proposal_to_vote(&self) -> Option<Block> {
        let mut chosen_proposal = None;
        let mut min_vrf_number = U256::MAX;
        for (_, b) in &*self.proposal_candidates.lock() {
            let vrf_number = U256::from_big_endian(
                b.vrf_proof().unwrap().to_hash().unwrap().as_ref(),
            );
            if vrf_number < min_vrf_number {
                chosen_proposal = Some(b.clone());
                min_vrf_number = vrf_number
            }
        }
        diem_debug!("choose_proposal_to_vote: {:?}", chosen_proposal);
        chosen_proposal
    }

    fn next_round(&self, round: Round) {
        *self.current_round.lock() = round;
        self.proposal_candidates.lock().clear();
    }
}
