// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! Consensus for the Diem Core blockchain
//!
//! The consensus protocol implemented is DiemBFT (based on
//! [HotStuff](https://arxiv.org/pdf/1803.05069.pdf)).

#![cfg_attr(not(feature = "fuzzing"), deny(missing_docs))]
#![cfg_attr(feature = "fuzzing", allow(dead_code))]

mod block_storage;
mod consensusdb;
mod counters;
mod epoch_manager;
mod error;
mod liveness;
mod logging;
mod metrics_safety_rules;
pub(crate) mod network;
#[cfg(test)]
mod network_tests;
mod pending_votes;
mod persistent_liveness_storage;
mod round_manager;
mod state_computer;
mod state_replication;
#[cfg(any(test, feature = "fuzzing"))]
mod test_utils;
#[cfg(test)]
mod twins;
mod txn_manager;
mod util;

/// DiemBFT implementation
pub mod consensus_provider;

pub use self::network::NetworkTask;
pub use consensusdb::ConsensusDB;
#[cfg(feature = "fuzzing")]
pub use round_manager::round_manager_fuzzing;
pub use util::{
    config_subscription::gen_consensus_reconfig_subscription, TestCommand,
};
