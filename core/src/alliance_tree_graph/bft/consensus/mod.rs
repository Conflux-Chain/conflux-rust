// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![cfg_attr(feature = "fuzzing", allow(dead_code))]

#[allow(missing_docs)]
pub mod chained_bft;

mod util;

#[cfg(feature = "fuzzing")]
pub use chained_bft::event_processor_fuzzing;

/// Defines the public consensus provider traits to implement for
/// use in the Libra Core blockchain.
pub mod consensus_provider;

mod counters;

pub mod consensus_types;
pub mod safety_rules;
pub mod state_computer;
mod state_replication;
