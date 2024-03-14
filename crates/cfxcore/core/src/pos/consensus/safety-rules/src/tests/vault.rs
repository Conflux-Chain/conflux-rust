// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{tests::suite, PersistentSafetyStorage, SafetyRulesManager};
use diem_crypto::{bls::BLSPrivateKey, Uniform};
use diem_secure_storage::{KVStorage, Storage, VaultStorage};
use diem_types::validator_signer::ValidatorSigner;
use diem_vault_client::dev::{self, ROOT_TOKEN};

/// A test for verifying VaultStorage properly supports the SafetyRule backend.
/// This test depends on running Vault, which can be done by using the provided
/// docker run script in `docker/vault/run.sh`
#[test]
fn test() {
    if dev::test_host_safe().is_none() {
        return;
    }

    let boolean_values = [false, true];
    for verify_vote_proposal_signature in &boolean_values {
        for export_consensus_key in &boolean_values {
            suite::run_test_suite(&safety_rules(
                *verify_vote_proposal_signature,
                *export_consensus_key,
            ));
        }
    }
}

fn safety_rules(
    verify_vote_proposal_signature: bool, export_consensus_key: bool,
) -> suite::Callback {
    Box::new(move || {
        let signer = ValidatorSigner::from_int(0);
        let mut storage = Storage::from(VaultStorage::new(
            dev::test_host(),
            ROOT_TOKEN.to_string(),
            None,
            None,
            None,
            true,
            None,
            None,
        ));
        storage.reset_and_clear().unwrap();

        let waypoint =
            crate::test_utils::validator_signers_to_waypoint(&[&signer]);
        let storage = PersistentSafetyStorage::initialize(
            storage,
            signer.author(),
            signer.private_key().clone(),
            waypoint,
            true,
        );
        let safety_rules_manager = SafetyRulesManager::new_local(
            storage,
            verify_vote_proposal_signature,
            export_consensus_key,
            None,
            Default::default(),
        );
        let safety_rules = safety_rules_manager.client();
        (
            safety_rules,
            signer,
            if verify_vote_proposal_signature {
                Some(BLSPrivateKey::generate_for_testing())
            } else {
                None
            },
        )
    })
}
