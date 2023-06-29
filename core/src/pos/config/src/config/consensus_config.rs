// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::config::SafetyRulesConfig;
use diem_types::{
    account_address::AccountAddress, block_info::Round, chain_id::ChainId,
    validator_verifier::ValidatorVerifier,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsensusConfig {
    pub contiguous_rounds: u32,
    pub max_block_size: u64,
    pub max_pruned_blocks_in_mem: usize,
    // Timeout for consensus to get an ack from mempool for executed
    // transactions (in milliseconds)
    pub mempool_executed_txn_timeout_ms: u64,
    // Timeout for consensus to pull transactions from mempool and get a
    // response (in milliseconds)
    pub mempool_txn_pull_timeout_ms: u64,
    pub round_initial_timeout_ms: u64,
    pub cip113_round_initial_timeout_ms: u64,
    pub cip113_transition_epoch: u64,

    pub proposer_type: ConsensusProposerType,
    pub safety_rules: SafetyRulesConfig,
    // Only sync committed transactions but not vote for any pending blocks.
    // This is useful when validators coordinate on the latest version to
    // apply a manual transaction.
    pub sync_only: bool,
    // how many times to wait for txns from mempool when propose
    pub mempool_poll_count: u64,

    pub chain_id: ChainId,

    pub hardcoded_epoch_committee: BTreeMap<u64, ValidatorVerifier>,
}

impl Default for ConsensusConfig {
    fn default() -> ConsensusConfig {
        ConsensusConfig {
            contiguous_rounds: 2,
            max_block_size: 1000,
            max_pruned_blocks_in_mem: 100,
            mempool_txn_pull_timeout_ms: 5000,
            mempool_executed_txn_timeout_ms: 1000,
            // TODO(lpl): Decide value.
            // 60 epochs should have been generated in 4 minutes.
            round_initial_timeout_ms: 60_000,
            cip113_round_initial_timeout_ms: 30_000,
            cip113_transition_epoch: 12365,
            proposer_type: ConsensusProposerType::VrfProposer,
            safety_rules: SafetyRulesConfig::default(),
            sync_only: false,
            mempool_poll_count: 1,
            chain_id: Default::default(),
            hardcoded_epoch_committee: Default::default(),
        }
    }
}

impl ConsensusConfig {
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.safety_rules.set_data_dir(data_dir);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ConsensusProposerType {
    // Choose the smallest PeerId as the proposer
    FixedProposer,
    // Round robin rotation of proposers
    RotatingProposer,
    // Pre-specified proposers for each round,
    // or default proposer if round proposer not
    // specified
    RoundProposer(HashMap<Round, AccountAddress>),
    // TODO(lpl): Add threshold?
    VrfProposer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaderReputationConfig {
    pub active_weights: u64,
    pub inactive_weights: u64,
}
