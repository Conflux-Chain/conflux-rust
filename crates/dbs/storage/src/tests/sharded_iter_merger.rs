#[test]
fn test_key_prefix_and_shard_id() {
    // Check special byte keys.
    let mut byte_keys = vec![vec![]];
    let mut last_round_start_index = 0;
    for _byte_key_len in 1..5 {
        let last_round_end_index = byte_keys.len();
        for key_i in last_round_start_index..last_round_end_index {
            for i in 0..16 {
                let mut key = byte_keys[key_i].clone();
                key.push(i);
                byte_keys.push(key);
            }
        }
        last_round_start_index = last_round_end_index;
    }

    byte_keys.sort();

    let num_shards = 256;

    let mut prev_prefix_to_map = 0;
    for key in &byte_keys {
        let prefix_to_map = key.key_prefix_to_map();
        assert!(
            prefix_to_map >= prev_prefix_to_map,
            "key {:?}, prev_prefix_to_map {}, prefix_to_map {}",
            key,
            prefix_to_map,
            prev_prefix_to_map
        );
        prev_prefix_to_map = prefix_to_map;

        assert_eq!(
            key_to_shard_id(key, num_shards),
            number_key_to_shard_id((prefix_to_map as i64) << 32, num_shards),
            "{:?} 0x{:08x}",
            key,
            prefix_to_map
        );
        assert_eq!(
            ((prefix_to_map as i64) << 32).key_prefix_to_map() ^ 0x80000000,
            prefix_to_map
        );
    }
}

#[test]
fn test_sharded_iter_merger() -> Result<()> {
    let mut merger = ShardedIterMerger::new();
    let num_shards = 64;
    let max_keys = 500000;
    let mut shard_sizes = vec![max_keys, max_keys, max_keys, 1, 1, 1, 1, 1];
    shard_sizes.resize_with(num_shards, || 0);
    let mut rng = ChaChaRng::from_entropy();
    shard_sizes.shuffle(&mut rng);
    let mut shards = vec![];
    for _i in 0..num_shards {
        shards.push(vec![]);
    }
    let total_keys: usize = shard_sizes.iter().sum();
    let mut sorted = vec![];
    while sorted.len() != total_keys {
        let number_key = rng.gen();
        let shard_id = number_key_to_shard_id(number_key, num_shards);
        if shards[shard_id].len() != shard_sizes[shard_id] {
            sorted.push((number_key, ()));
            let r: Result<_> = Ok((number_key, ()));
            shards[shard_id].push(r);
        }
    }
    for mut shard in shards {
        shard.sort_by(|r1, r2| r1.as_ref().unwrap().cmp(r2.as_ref().unwrap()));
        merger.push_shard_iter(convert(shard.into_iter()))?;
    }
    sorted.sort();

    println!("test_sharded_iter_merger(): Initialization done.");
    for expected_key in sorted {
        let got = merger.next()?.unwrap();
        assert_eq!(expected_key, got);
    }
    assert_eq!(merger.next()?, None);
    println!("test_sharded_iter_merger(): Iteration done.");

    Ok(())
}

use crate::impls::{
    errors::Result,
    storage_db::kvdb_sqlite_sharded::{
        key_to_shard_id, number_key_to_shard_id, KeyPrefixToMap,
        ShardedIterMerger,
    },
};
use fallible_iterator::{convert, FallibleIterator};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
