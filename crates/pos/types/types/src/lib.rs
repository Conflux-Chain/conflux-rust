// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

pub use account_address::AccountAddress as PeerId;

pub mod account_address;
pub mod account_config;
pub mod block_info;
pub mod block_metadata;
pub mod chain_id;
pub mod contract_event;
pub mod epoch_change;
pub mod epoch_state;
pub mod event;
pub mod ledger_info;
pub mod mempool_status;
pub mod network_address;
pub mod on_chain_config;
pub mod proof;
#[cfg(any(test, feature = "fuzzing"))]
pub mod proptest_types;
#[cfg(any(test, feature = "fuzzing"))]
pub mod test_helpers;
pub mod transaction;
pub mod validator_config;
pub mod validator_info;
pub mod validator_signer;
pub mod validator_verifier;
pub mod vm_status;

pub mod committed_block;
pub mod reward_distribution_event;
pub mod term_state;
#[cfg(test)]
mod unit_tests;
