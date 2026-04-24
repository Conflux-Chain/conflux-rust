// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

mod configurable_validator_signer;
mod consensus_state;
mod error;
mod logging;
mod persistent_safety_storage;
mod safety_rules;

pub use crate::{
    consensus_state::ConsensusState, error::Error,
    persistent_safety_storage::PersistentSafetyStorage,
    safety_rules::SafetyRules,
};

/// Create a SafetyRules instance.
///
/// The author and keys are threaded directly from the runtime rather than read
/// from `SafetyRulesConfig`, because they're always overwritten from
/// Conflux-side config at startup.
pub fn create_safety_rules(
    config: &diem_config::config::SafetyRulesConfig,
    author: diem_types::PeerId,
    consensus_private_key: diem_types::validator_config::ConsensusPrivateKey,
    vrf_private_key: Option<
        diem_types::validator_config::ConsensusVRFPrivateKey,
    >,
    export_consensus_key: bool,
) -> SafetyRules {
    use diem_secure_storage::{KVStorage, Storage};
    use std::convert::TryInto;

    let backend = &config.backend;
    let internal_storage: Storage =
        backend.try_into().expect("Unable to initialize storage");
    if let Err(error) = internal_storage.available() {
        panic!("Storage is not available: {:?}", error);
    }

    let persistent_storage = PersistentSafetyStorage::initialize(
        internal_storage,
        author,
        consensus_private_key,
        config.enable_cached_safety_data,
    );

    SafetyRules::new(
        persistent_storage,
        export_consensus_key,
        vrf_private_key,
        author,
    )
}

#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzzing_utils;

#[cfg(any(test, feature = "fuzzing"))]
pub use crate::fuzzing_utils::fuzzing;

#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

#[cfg(test)]
mod tests;
