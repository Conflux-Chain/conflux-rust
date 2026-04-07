// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::persistent_liveness_storage::PersistentLivenessStorage;
use consensus_types::{
    block::Block, block_data::BlockData, timeout::Timeout, vote::Vote,
    vote_proposal::MaybeSignedVoteProposal,
};
use diem_metrics::monitor;
use diem_types::{
    epoch_state::EpochState, validator_config::ConsensusSignature,
};
use safety_rules::{ConsensusState, Error, TSafetyRules};
use std::sync::Arc;

/// Wrap safety rules with counters.
pub struct MetricsSafetyRules {
    inner: Box<dyn TSafetyRules + Send + Sync>,
    storage: Arc<dyn PersistentLivenessStorage>,
}

impl MetricsSafetyRules {
    pub fn new(
        inner: Box<dyn TSafetyRules + Send + Sync>,
        storage: Arc<dyn PersistentLivenessStorage>,
    ) -> Self {
        Self { inner, storage }
    }

    pub fn perform_initialize(&mut self) -> Result<(), Error> {
        let db = self.storage.pos_ledger_db();
        // Determine the latest epoch from the DB, then load the
        // epoch-ending LI that transitions into it.
        let latest_li = db.get_latest_ledger_info().map_err(|e| {
            Error::InternalError(format!(
                "Unable to retrieve latest ledger info: {}",
                e
            ))
        })?;
        let target_epoch = latest_li.ledger_info().next_block_epoch();
        let proof = db
            .get_epoch_ending_ledger_infos(
                target_epoch.saturating_sub(1),
                target_epoch,
            )
            .map_err(|e| {
                Error::InternalError(format!(
                    "Unable to retrieve epoch ending LI: {}",
                    e
                ))
            })?;
        let li = proof.ledger_info_with_sigs.last().ok_or_else(|| {
            Error::InternalError("No epoch ending LI found".into())
        })?;
        let epoch_state =
            li.ledger_info().next_epoch_state().ok_or_else(|| {
                Error::InternalError(
                    "Epoch ending LI has no next_epoch_state".into(),
                )
            })?;
        self.initialize(epoch_state)
    }
}

impl TSafetyRules for MetricsSafetyRules {
    fn consensus_state(&mut self) -> Result<ConsensusState, Error> {
        monitor!("safety_rules", self.inner.consensus_state())
    }

    fn initialize(&mut self, epoch_state: &EpochState) -> Result<(), Error> {
        monitor!("safety_rules", self.inner.initialize(epoch_state))
    }

    fn construct_and_sign_vote(
        &mut self, vote_proposal: &MaybeSignedVoteProposal,
    ) -> Result<Vote, Error> {
        let mut result = monitor!(
            "safety_rules",
            self.inner.construct_and_sign_vote(vote_proposal)
        );

        if let Err(Error::NotInitialized(_res)) = result {
            self.perform_initialize()?;
            result = monitor!(
                "safety_rules",
                self.inner.construct_and_sign_vote(vote_proposal)
            );
        }
        result
    }

    fn sign_proposal(&mut self, block_data: BlockData) -> Result<Block, Error> {
        let mut result = monitor!(
            "safety_rules",
            self.inner.sign_proposal(block_data.clone())
        );
        if let Err(Error::NotInitialized(_res)) = result {
            self.perform_initialize()?;
            result =
                monitor!("safety_rules", self.inner.sign_proposal(block_data));
        }
        result
    }

    fn sign_timeout(
        &mut self, timeout: &Timeout,
    ) -> Result<ConsensusSignature, Error> {
        let mut result =
            monitor!("safety_rules", self.inner.sign_timeout(timeout));
        if let Err(Error::NotInitialized(_res)) = result {
            self.perform_initialize()?;
            result = monitor!("safety_rules", self.inner.sign_timeout(timeout));
        }
        result
    }

    fn start_voting(&mut self, initialize: bool) -> Result<(), Error> {
        monitor!("safety_rules", self.inner.start_voting(initialize))
    }

    fn stop_voting(&mut self) -> Result<(), Error> {
        monitor!("safety_rules", self.inner.stop_voting())
    }
}
