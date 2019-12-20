// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[test]
fn test_slice_verifier() {
    // Slice empty mpt.
    //    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    //    let chunk_size = 1000;
    //
    //    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    //    let mut slicer_chunk_bounds = vec![];
    //    loop {
    //        slicer.advance(chunk_size).unwrap();
    //        match slicer.get_range_end_key() {
    //            Some(key) => {
    //                slicer_chunk_bounds.push(Vec::from(key));
    //                println!("{:?}", key);
    //            }
    //            None => {
    //                break;
    //            }
    //        }
    //    }
    //    assert_eq!(0, slicer_chunk_bounds.len());

    // Slice non-empty mpt.
    let mut rng = get_rng_for_test();
    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();
    keys.sort();
    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: keys
            .iter()
            .map(|k| {
                (
                    k[..].into(),
                    [&k[..], &k[..], &k[..], &k[..]].concat()
                        [0..(6 + rng.gen::<usize>() % 10)]
                        .into(),
                )
            })
            .collect(),
    };

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mut size_sum = Vec::with_capacity(keys.len());
    let mut total_rlp_size = 0;
    for (key, value) in &mpt_kv_iter.kv {
        total_rlp_size += rlp_key_value_len(key.len() as u16, value.len());
        size_sum.push(total_rlp_size);
    }
    let chunk_size = size_sum.last().unwrap() / 5 as u64;

    // Slice by scanning to get chunk contents.
    let mut right_bound = 0;
    let mut start_size = 0;
    let mut right_bounds = vec![];
    let mut chunk_key_bounds = vec![Some(vec![])];
    while right_bound < keys.len() {
        if size_sum[right_bound] > chunk_size + start_size {
            right_bounds.push(right_bound);
            start_size = size_sum[right_bound - 1];
            chunk_key_bounds.push(Some(mpt_kv_iter.kv[right_bound].0.clone()));
        }
        right_bound += 1;
    }
    right_bounds.push(right_bound);
    chunk_key_bounds.push(None);

    // Slice by MptSlicer to get proofs.
    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    let mut slicer_chunk_proofs = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                slicer_chunk_proofs.push(Some(slicer.to_proof()));
            }
            None => {
                break;
            }
        }
    }
    slicer_chunk_proofs.push(None);
    let mut last_proof = None;
    let mut chunk_start_offset = 0;
    for i in 0..slicer_chunk_proofs.len() {
        let chunk_bound = right_bounds[i];
        println!(
            "test chunk {}, chunk range {}..{}, chunk_last_kvs {:?}",
            i,
            chunk_start_offset,
            chunk_bound,
            &mpt_kv_iter.kv[chunk_bound - 3..chunk_bound],
        );
        assert!(MptSliceVerifier::new(
            last_proof,
            &**chunk_key_bounds[i].as_ref().unwrap(),
            slicer_chunk_proofs[i].as_ref(),
            chunk_key_bounds[i + 1].as_ref().map(|v| &**v),
            merkle_root
        )
        .restore(
            &mpt_kv_iter.kv[chunk_start_offset..chunk_bound]
                .iter()
                .map(|kv| &*kv.0)
                .collect(),
            &mpt_kv_iter.kv[chunk_start_offset..chunk_bound]
                .iter()
                .map(|kv| kv.1.clone())
                .collect(),
        )
        .map(|result| result.is_valid)
        .unwrap_or(false));
        // Check incomplete chunk.
        for j_omit in [
            (chunk_start_offset..min(chunk_start_offset + 5, chunk_bound))
                .collect::<Vec<usize>>(),
            vec![(chunk_start_offset + chunk_bound) / 2],
            (max(chunk_start_offset, chunk_bound - 5)..chunk_bound)
                .collect::<Vec<usize>>(),
        ]
        .concat()
        {
            println!(
                "test key omit, chunk {}, chunk range {}..{}, omit index {}, kv: {:?},\
                chunk_last_kvs {:?}",
                i, chunk_start_offset, chunk_bound, j_omit, mpt_kv_iter.kv[j_omit],
                &mpt_kv_iter.kv[chunk_bound - 3..chunk_bound],
            );
            let mut keys = Vec::with_capacity(chunk_bound - chunk_start_offset);
            let mut values =
                Vec::with_capacity(chunk_bound - chunk_start_offset);
            for index in chunk_start_offset..chunk_bound {
                if index != j_omit {
                    keys.push(&*mpt_kv_iter.kv[index].0);
                    values.push(mpt_kv_iter.kv[index].1.clone());
                }
            }
            assert!(!MptSliceVerifier::new(
                last_proof,
                &**chunk_key_bounds[i].as_ref().unwrap(),
                slicer_chunk_proofs[i].as_ref(),
                chunk_key_bounds[i + 1].as_ref().map(|v| &**v),
                merkle_root,
            )
            .restore(&keys, &values)
            .map(|result| result.is_valid)
            .unwrap_or(false));
        }
        last_proof = slicer_chunk_proofs[i].as_ref();
        chunk_start_offset = chunk_bound;
    }
}

use crate::storage::{
    impls::{
        merkle_patricia_trie::{mpt_cursor::rlp_key_value_len, MptMerger},
        snapshot_sync::restoration::mpt_slice_verifier::MptSliceVerifier,
    },
    tests::{
        generate_keys, get_rng_for_test, snapshot::FakeSnapshotMptDb,
        DumpedDeltaMptIterator, TEST_NUMBER_OF_KEYS,
    },
    MptSlicer,
};
use rand::Rng;
use std::cmp::{max, min};
