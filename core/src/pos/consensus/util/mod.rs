// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_crypto::HashValue;

pub mod config_subscription;
#[cfg(any(test, feature = "fuzzing"))]
pub mod mock_time_service;
pub mod time_service;

/// Test command sent by RPCs to construct attack cases.
#[derive(Debug)]
pub enum TestCommand {
    /// Make the node vote for the given proposal regardless of its consensus
    /// state. It will not vote if the proposal was not received.
    ForceVoteProposal(HashValue),
}
