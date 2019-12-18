// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[test]
fn test_slicing_position() {
    // Slice empty mpt.
    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    let chunk_size = 1000;

    let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
    let mut slicer_chunk_bounds = vec![];
    loop {
        slicer.advance(chunk_size).unwrap();
        match slicer.get_range_end_key() {
            Some(key) => {
                slicer_chunk_bounds.push(Vec::from(key));
                println!("{:?}", key);
            }
            None => {
                break;
            }
        }
    }
    assert_eq!(0, slicer_chunk_bounds.len());

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

    let mut size_sum = Vec::with_capacity(keys.len());
    let mut total_rlp_size = 0;
    for (key, value) in &mpt_kv_iter.kv {
        total_rlp_size += rlp_key_value_len(key.len() as u16, value.len());
        size_sum.push(total_rlp_size);
    }

    let mut snapshot_mpt = FakeSnapshotMptDb::default();
    MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    for expected_chunks in 5..20 {
        let chunk_size = size_sum.last().unwrap() / expected_chunks;
        let mut right_bound = 0;
        let mut start_size = 0;
        let mut chunk_sizes = vec![];
        let mut chunk_right_bounds = vec![];
        while right_bound < keys.len() {
            if size_sum[right_bound] > chunk_size + start_size {
                chunk_sizes.push(size_sum[right_bound - 1] - start_size);
                start_size = size_sum[right_bound - 1];
                chunk_right_bounds.push(mpt_kv_iter.kv[right_bound].0.clone());
            }
            right_bound += 1;
        }
        chunk_sizes.push(size_sum.last().unwrap() - start_size);

        println!(
            "chunk_size_limit = {}, chunk_size {:?}",
            chunk_size, chunk_sizes
        );

        // Slice by MptSlicer.
        let mut slicer = MptSlicer::new(&mut snapshot_mpt).unwrap();
        let mut slicer_chunk_bounds = vec![];
        loop {
            slicer.advance(chunk_size).unwrap();
            match slicer.get_range_end_key() {
                Some(key) => {
                    slicer_chunk_bounds.push(Vec::from(key));
                }
                None => {
                    break;
                }
            }
        }
        assert_eq!(chunk_right_bounds, slicer_chunk_bounds);
    }
}

use crate::storage::{
    impls::merkle_patricia_trie::{mpt_cursor::rlp_key_value_len, MptMerger},
    tests::{
        generate_keys, get_rng_for_test, snapshot::FakeSnapshotMptDb,
        DumpedDeltaMptIterator, TEST_NUMBER_OF_KEYS,
    },
    MptSlicer,
};
use rand::Rng;
