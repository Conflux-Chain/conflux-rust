// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::PosLedgerDB;
use diem_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
use diem_proptest_helpers::Index;
use diem_temppath::TempPath;
use diem_types::{
    account_address::AccountAddress,
    block_metadata::NewBlockEvent,
    contract_event::ContractEvent,
    event::EventKey,
    proptest_types::{AccountInfoUniverse, ContractEventGen},
};
use itertools::Itertools;
use move_core_types::{language_storage::TypeTag, move_resource::MoveResource};
use proptest::{
    collection::{hash_set, vec},
    prelude::*,
    strategy::Union,
};
use rand::Rng;
use std::collections::HashMap;

fn save(
    store: &EventStore, version: Version, events: &[ContractEvent],
) -> HashValue {
    let mut cs = ChangeSet::new();
    let root_hash = store.put_events(version, events, &mut cs).unwrap();
    assert_eq!(
        cs.counter_bumps(version).get(LedgerCounter::EventsCreated),
        events.len()
    );
    store.db.write_schemas(cs.batch, true).unwrap();

    root_hash
}

#[test]
fn test_put_empty() {
    let tmp_dir = TempPath::new();
    let db = PosLedgerDB::new_for_test(&tmp_dir);
    let store = &db.event_store;
    let mut cs = ChangeSet::new();
    assert_eq!(
        store.put_events(0, &[], &mut cs).unwrap(),
        *ACCUMULATOR_PLACEHOLDER_HASH
    );
}

#[test]
fn test_error_on_get_from_empty() {
    let tmp_dir = TempPath::new();
    let db = PosLedgerDB::new_for_test(&tmp_dir);
    let store = &db.event_store;

    assert!(store
        .get_event_with_proof_by_version_and_index(100, 0)
        .is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_put_get_verify(events in vec(any::<ContractEvent>().no_shrink(), 1..100)) {
        let tmp_dir = TempPath::new();
        let db = PosLedgerDB::new_for_test(&tmp_dir);
        let store = &db.event_store;

        let root_hash = save(store, 100, &events);

        // get and verify each and every event with proof
        for (idx, expected_event) in events.iter().enumerate() {
            let (event, proof) = store
                .get_event_with_proof_by_version_and_index(100, idx as u64)
                .unwrap();
            prop_assert_eq!(&event, expected_event);
            proof.verify(root_hash, event.hash(), idx as u64).unwrap();
        }
        // error on index >= num_events
        prop_assert!(store
            .get_event_with_proof_by_version_and_index(100, events.len() as u64)
            .is_err());
    }

}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]

    #[test]
    fn test_get_all_events_by_version(
        events1 in vec(any::<ContractEvent>().no_shrink(), 1..100),
        events2 in vec(any::<ContractEvent>().no_shrink(), 1..100),
        events3 in vec(any::<ContractEvent>().no_shrink(), 1..100),
    ) {

        let tmp_dir = TempPath::new();
        let db = PosLedgerDB::new_for_test(&tmp_dir);
        let store = &db.event_store;
        // Save 3 chunks at different versions
        save(store, 99 /*version*/, &events1);
        save(store, 100 /*version*/, &events2);
        save(store, 101 /*version*/, &events3);

        // Now get all events at each version and verify that it matches what is expected.
        let events_99 = store.get_events_by_version(99 /*version*/).unwrap();
        prop_assert_eq!(events_99, events1);

        let events_100 = store.get_events_by_version(100 /*version*/).unwrap();
        prop_assert_eq!(events_100, events2);

        let events_101 = store.get_events_by_version(101 /*version*/).unwrap();
        prop_assert_eq!(events_101, events3);

        // Now query a version that doesn't exist and verify that no results come back
        let events_102 = store.get_events_by_version(102 /*version*/).unwrap();
        prop_assert_eq!(events_102.len(), 0);
    }
}

// fn traverse_events_by_key(
//     store: &EventStore, event_key: &EventKey, ledger_version: Version,
// ) -> Vec<ContractEvent> {
//     const LIMIT: u64 = u64::MAX;
//
//     let mut seq_num = 0;
//
//     let mut event_keys = Vec::new();
//     let mut last_batch_len = LIMIT;
//     loop {
//         let mut batch = store
//             .lookup_events_by_key(&event_key, seq_num, LIMIT, ledger_version)
//             .unwrap();
//         if last_batch_len < LIMIT {
//             assert!(batch.is_empty());
//         }
//         if batch.is_empty() {
//             break;
//         }
//         event_keys.extend(batch.iter());
//         seq_num += batch.len() as u64;
//     }
//
//     event_keys
//         .into_iter()
//         .map(|(ver, idx)| {
//             store
//                 .get_event_with_proof_by_version_and_index(ver, idx)
//                 .unwrap()
//                 .0
//         })
//         .collect()
// }

// proptest! {
//     #![proptest_config(ProptestConfig::with_cases(10))]
//
//     #[test]
//     fn test_index_get(
//         mut universe in any_with::<AccountInfoUniverse>(3),
//         gen_batches in vec(vec((any::<Index>(), any::<ContractEventGen>()),
// 0..=2), 0..100),     ) {
//         let event_batches = gen_batches
//             .into_iter()
//             .map(|gens| {
//                 gens.into_iter()
//                     .map(|(index, gen)| gen.materialize(*index, &mut
// universe))                     .collect()
//             })
//             .collect();
//
//         test_index_get_impl(event_batches);
//     }
// }

// fn test_index_get_impl(event_batches: Vec<Vec<ContractEvent>>) {
//     // Put into db.
//     let tmp_dir = TempPath::new();
//     let db = DiemDB::new_for_test(&tmp_dir);
//     let store = &db.event_store;
//
//     let mut cs = ChangeSet::new();
//     event_batches.iter().enumerate().for_each(|(ver, events)| {
//         store.put_events(ver as u64, events, &mut cs).unwrap();
//     });
//     store.db.write_schemas(cs.batch);
//     let ledger_version_plus_one = event_batches.len() as u64;
//
//     assert_eq!(
//         store
//             .get_events_by_version_iter(0, event_batches.len())
//             .unwrap()
//             .collect::<Result<Vec<_>>>()
//             .unwrap(),
//         event_batches,
//     );
//
//     // Calculate expected event sequence per access_path.
//     let mut events_by_event_key = HashMap::new();
//     event_batches
//         .into_iter()
//         .enumerate()
//         .for_each(|(ver, batch)| {
//             batch.into_iter().for_each(|e| {
//                 let mut events_and_versions = events_by_event_key
//                     .entry(*e.key())
//                     .or_insert_with(Vec::new);
//                 events_and_versions.push((e, ver as Version));
//             })
//         });
//
//     // Fetch and check.
//     events_by_event_key
//         .into_iter()
//         .for_each(|(path, events_and_versions)| {
//             // Check sequence number
//             let mut prev_ver = 0;
//             let mut iter = events_and_versions.iter().enumerate().peekable();
//             while let Some((mut seq, (_, ver))) = iter.next() {
//                 let mid = prev_ver + (*ver - prev_ver) / 2;
//                 // possible multiple emits of the event in the same version
//                 let mut last_seq_in_same_version = seq;
//                 while let Some((next_seq, (_, next_ver))) = iter.peek() {
//                     if next_ver != ver {
//                         break;
//                     }
//                     last_seq_in_same_version = *next_seq;
//                     iter.next();
//                 }
//
//                 prev_ver = *ver;
//             }
//
//             // Fetch by key
//             let events = events_and_versions
//                 .into_iter()
//                 .map(|(e, _)| e)
//                 .collect::<Vec<_>>();
//             let traversed =
//                 traverse_events_by_key(&store, &path,
// ledger_version_plus_one);             assert_eq!(events, traversed);
//         });
// }

prop_compose! {
    fn arb_new_block_events()(
        address in any::<AccountAddress>(),
        mut version in 1..10000u64,
        mut timestamp in 0..1000000u64, // initial timestamp
        block_bumps in vec(
            prop_oneof![
                Just((1, 0)), // NIL Block
                (1..100u64, 1..100u64) // normal block
            ], // version and timestamp bump
            1..100,
        )
    ) -> Vec<(Version, ContractEvent)> {
        let mut round = 0;
        block_bumps.into_iter().map(|(v, t)| {
            version += v;
            timestamp += t;
            let new_block_event = NewBlockEvent::new(
                round,
                address, // proposer
                Vec::new(), // prev block voters
                timestamp,
            );
            let event = ContractEvent::new(
                new_block_event_key(),
                bcs::to_bytes(&new_block_event).unwrap(),
            );
            round += 1;
            (version, event)
        }).collect()
    }
}
