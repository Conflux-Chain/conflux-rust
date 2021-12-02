// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub(crate) mod proposal_generator;
pub(crate) mod proposer_election;
pub(crate) mod rotating_proposer_election;
pub(crate) mod round_proposer_election;
pub(crate) mod round_state;
pub(crate) mod vrf_proposer_election;

#[cfg(test)]
mod rotating_proposer_test;
#[cfg(test)]
mod round_proposer_test;
#[cfg(test)]
mod round_state_test;
