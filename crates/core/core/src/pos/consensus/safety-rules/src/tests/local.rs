// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{test_utils, tests::suite, SafetyRulesManager};
use diem_crypto::{bls::BLSPrivateKey, Uniform};
use diem_types::validator_signer::ValidatorSigner;

#[test]
fn test() {
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
        let storage = test_utils::test_storage(&signer);
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
