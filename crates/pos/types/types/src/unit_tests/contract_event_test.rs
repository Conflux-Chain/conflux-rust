// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    contract_event::{ContractEvent, EventWithProof},
    event::EventKey,
};
use bcs::test_helpers::assert_canonical_encode_decode;
use proptest::prelude::*;

proptest! {
    #[test]
    fn event_bcs_roundtrip(event in any::<ContractEvent>()) {
        assert_canonical_encode_decode(event);
    }

    #[test]
    fn event_with_proof_bcs_roundtrip(event_with_proof in any::<EventWithProof>()) {
        assert_canonical_encode_decode(event_with_proof);
    }
}

#[test]
fn test_event_json_serialize() {
    let event_key = EventKey::random();
    let contract_event = ContractEvent::new(event_key, vec![0u8]);
    let contract_json = serde_json::to_string(&contract_event)
        .expect("event serialize to json should succeed.");
    let contract_event2: ContractEvent =
        serde_json::from_str(contract_json.as_str()).unwrap();
    assert_eq!(contract_event, contract_event2)
}
