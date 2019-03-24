// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

fn generate_keys() -> Vec<[u8; 4]> {
    let number_of_keys = 100000;
    let mut rng = get_rng_for_test();

    let mut keys_num: Vec<u32> = Default::default();

    for i in 0..number_of_keys {
        keys_num.push(rng.gen());
    }

    keys_num.sort();

    let mut keys: Vec<[u8; 4]> = Default::default();
    let mut last_key = keys_num[0];
    for key in &keys_num[1..number_of_keys] {
        if *key != last_key {
            keys.push(unsafe { mem::transmute::<u32, [u8; 4]>(key.clone()) });
        }
        last_key = *key;
    }

    rng.shuffle(&mut keys);
    keys
}

fn get_rng_for_test() -> ChaChaRng { ChaChaRng::from_seed([123; 32]) }

#[test]
fn test_set_get() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_testing();
    let mut state = state_manager.get_state_at(H256::default()).unwrap();
    let mut keys: Vec<[u8; 4]> = generate_keys()
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();

    println!("Testing with {} set operations.", keys.len());

    for key in &keys {
        state.set(key, key).expect("Failed to insert key.");
    }

    rng.shuffle(keys.as_mut());

    for key in &keys {
        let value = state
            .get(key)
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = key.eq(value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id = H256::default();
    epoch_id[0] = 1;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();
}

#[test]
fn test_get_set_at_second_commit() {
    let rng = get_rng_for_test();
    let state_manager = new_state_manager_for_testing();
    let keys: Vec<[u8; 4]> = generate_keys();
    let set_size = 10000;
    let (keys_0, keys_1_new, keys_remain, keys_1_overwritten) = (
        &keys[0..set_size * 2],
        &keys[set_size * 2..set_size * 3],
        &keys[0..set_size],
        &keys[set_size..set_size * 2],
    );

    let parent_epoch_0 = H256::default();
    let mut state_0 = state_manager.get_state_at(parent_epoch_0).unwrap();
    println!("Setting state_0 with {} keys.", keys_0.len());

    for key in keys_0 {
        state_0.set(key, key).expect("Failed to insert key.");
    }

    let mut epoch_id_0 = H256::default();;
    epoch_id_0[0] = 1;
    state_0.compute_state_root().unwrap();
    state_0.commit(epoch_id_0).unwrap();

    let mut state_1 = state_manager.get_state_at(epoch_id_0).unwrap();
    println!("Set new {} keys for state_1.", keys_1_new.len(),);
    for key in keys_1_new {
        let value = vec![&key[..], &key[..]].concat();
        state_1
            .set(key, value.as_slice())
            .expect("Failed to insert key.");
    }

    println!(
        "Reading overlapping {} keys from state_0 and set new keys for state_1.",
        keys_1_overwritten.len(),
    );
    for key in keys_1_overwritten {
        let old_value = state_1
            .get(key)
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = key.eq(old_value.as_ref());
        assert_eq!(equal, true);
        let value = vec![&key[..], &key[..]].concat();
        state_1
            .set(key, value.as_slice())
            .expect("Failed to insert key.");
    }

    println!(
        "Reading untouched {} keys from state_0 in state_1.",
        keys_remain.len(),
    );
    for key in keys_remain {
        let value = state_1
            .get(key)
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = key.eq(value.as_ref());
        assert_eq!(equal, true);
    }

    println!(
        "Reading modified {} keys in state_1.",
        keys_1_overwritten.len(),
    );
    for key in keys_1_overwritten {
        let value = state_1
            .get(key)
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let expected_value = vec![&key[..], &key[..]].concat();
        let equal = expected_value.eq(&value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id_1 = H256::default();;
    epoch_id_1[0] = 2;
    state_1.compute_state_root().unwrap();
    state_1.commit(epoch_id_1).unwrap();
}

#[test]
fn test_set_delete() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_testing();
    let mut state = state_manager.get_state_at(H256::default()).unwrap();
    let mut keys: Vec<[u8; 4]> = generate_keys();

    println!("Testing with {} set operations.", keys.len());

    for key in &keys {
        state.set(key, key).expect("Failed to insert key.");
    }

    rng.shuffle(keys.as_mut());

    println!("Testing with {} delete operations.", keys.len());
    let mut count = 0;
    for key in &keys {
        count += 1;
        let value = state
            .delete(key)
            .expect("Failed to delete key.")
            .expect("Failed to get key");
        let equal = key.eq(value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id = H256::default();
    epoch_id[0] = 1;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();
}

fn print(key: &[u8]) {
    print!("key = (");
    for char in key {
        print!(
            "{}, {}, ",
            CompressedPathRaw::first_nibble(*char),
            CompressedPathRaw::second_nibble(*char)
        );
    }
    println!(")");
}

#[test]
fn test_set_order() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_testing();
    let keys: Vec<[u8; 4]> = generate_keys()
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();

    let parent_epoch_0 = H256::default();
    let mut epoch_id = H256::default();
    let mut state_0 = state_manager.get_state_at(parent_epoch_0).unwrap();
    println!("Setting state_0 with {} keys.", keys.len());
    for key in &keys {
        state_0.set(key, key).expect("Failed to insert key.");
    }
    let merkle_0 = state_0.compute_state_root().unwrap();
    epoch_id[0] = 1;
    state_0.commit(epoch_id).unwrap();

    let mut state_1 = state_manager.get_state_at(parent_epoch_0).unwrap();
    println!("Setting state_1 with {} keys.", keys.len());
    for key in &keys {
        state_1.set(key, key).expect("Failed to insert key.");
    }
    let merkle_1 = state_1.compute_state_root().unwrap();
    epoch_id[0] = 2;
    state_1.commit(epoch_id).unwrap();

    let mut state_2 = state_manager.get_state_at(parent_epoch_0).unwrap();
    println!("Setting state_2 with {} keys.", keys.len());
    for key in keys.iter().rev() {
        state_2.set(key, key).expect("Failed to insert key.");
    }
    for key in &keys {
        assert_eq!(
            *state_2.get(key).expect("Failed to insert key.").unwrap(),
            *key
        );
    }
    let merkle_2 = state_2.compute_state_root().unwrap();
    epoch_id[0] = 3;
    state_2.commit(epoch_id).unwrap();

    assert_eq!(merkle_0, merkle_1);
    assert_eq!(merkle_0, merkle_2);
}

use super::{
    super::{
        impls::multi_version_merkle_patricia_trie::merkle_patricia_trie::CompressedPathRaw,
        state::*, state_manager::*,
    },
    new_state_manager_for_testing,
};
use cfx_types::H256;
use rand::{ChaChaRng, Rng, SeedableRng};
use std::mem;
