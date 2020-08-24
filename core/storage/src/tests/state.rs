// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[test]
fn test_empty_genesis_block() {
    let state_manager = new_state_manager_for_unit_test();

    let mut genesis_epoch_id = H256::default();
    genesis_epoch_id.as_bytes_mut()[0] = 1;
    {
        let mut genesis_state = state_manager.get_state_for_genesis_write();
        genesis_state.compute_state_root().unwrap();

        genesis_state.commit(genesis_epoch_id).unwrap();
    }

    state_manager
        .get_state_trees(
            &StateIndex::new_for_test_only_delta_mpt(&genesis_epoch_id),
            /* try_open = */ false,
        )
        .unwrap();
}

#[test]
fn test_set_get() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();
    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();

    println!("Testing with {} set operations.", keys.len());

    for key in &keys {
        state
            .set(StorageKey::AccountKey(key), key[..].into())
            .expect("Failed to insert key.");
    }

    keys.shuffle(&mut rng);

    for key in &keys {
        let value = state
            .get(StorageKey::AccountKey(key))
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = (&**key).eq(value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 1;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();
}

#[test]
fn test_get_set_at_second_commit() {
    let state_manager = new_state_manager_for_unit_test();
    let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    let set_size = TEST_NUMBER_OF_KEYS / 10;
    let (keys_0, keys_1_new, keys_remain, keys_1_overwritten) = (
        &keys[0..set_size * 2],
        &keys[set_size * 2..set_size * 3],
        &keys[0..set_size],
        &keys[set_size..set_size * 2],
    );

    let mut state_0 = state_manager.get_state_for_genesis_write();
    println!("Setting state_0 with {} keys.", keys_0.len());

    for key in keys_0 {
        state_0
            .set(StorageKey::AccountKey(key), key[..].into())
            .expect("Failed to insert key.");
    }

    let mut epoch_id_0 = H256::default();
    epoch_id_0.as_bytes_mut()[0] = 1;
    state_0.compute_state_root().unwrap();
    state_0.commit(epoch_id_0).unwrap();

    let mut state_1 = state_manager
        .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
            &epoch_id_0,
        ))
        .unwrap()
        .unwrap();
    println!("Set new {} keys for state_1.", keys_1_new.len());
    for key in keys_1_new {
        let value = vec![&key[..], &key[..]].concat();
        state_1
            .set(StorageKey::AccountKey(key), value.into())
            .expect("Failed to insert key.");
    }

    println!(
        "Reading overlapping {} keys from state_0 and set new keys for state_1.",
        keys_1_overwritten.len(),
    );
    for key in keys_1_overwritten {
        let old_value = state_1
            .get(StorageKey::AccountKey(key))
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = (&**key).eq(old_value.as_ref());
        assert_eq!(equal, true);
        let value = vec![&key[..], &key[..]].concat();
        state_1
            .set(StorageKey::AccountKey(key), value.into())
            .expect("Failed to insert key.");
    }

    println!(
        "Reading untouched {} keys from state_0 in state_1.",
        keys_remain.len(),
    );
    for key in keys_remain {
        let value = state_1
            .get(StorageKey::AccountKey(key))
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let equal = (&**key).eq(value.as_ref());
        assert_eq!(equal, true);
    }

    println!(
        "Reading modified {} keys in state_1.",
        keys_1_overwritten.len(),
    );
    for key in keys_1_overwritten {
        let value = state_1
            .get(StorageKey::AccountKey(key))
            .expect("Failed to get key.")
            .expect("Failed to get key");
        let expected_value = vec![&key[..], &key[..]].concat();
        let equal = expected_value.eq(&value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id_1 = H256::default();
    epoch_id_1.as_bytes_mut()[0] = 2;
    state_1.compute_state_root().unwrap();
    state_1.commit(epoch_id_1).unwrap();
}

#[test]
fn test_snapshot_random_read_performance() {
    let state_manager = new_state_manager_for_unit_test();
    let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);

    const EPOCHS: u8 = 20;
    println!(
        "Build {} epochs for testing, 10 epochs a snapshot.",
        2 * EPOCHS
    );
    let mut rng = get_rng_for_test();
    let range = Uniform::from(0..keys.len());
    const TXS: u32 = 20000;
    let mut epoch_keys = Vec::with_capacity(EPOCHS as usize * 2);
    for _epoch in 0..EPOCHS * 2 {
        let mut e_keys = Vec::with_capacity(TXS as usize * 2);
        for _key_idx in (-(TXS as i32) * 2)..0 {
            e_keys.push(keys[range.sample(&mut rng)].as_slice());
        }
        epoch_keys.push(e_keys);
    }

    println!("Initializing {} accounts", keys.len());
    const DEFAULT_BALANCE: u64 = 1_000_000_000;
    let mut state_0 = state_manager.get_state_for_genesis_write();
    for key in &keys {
        let mut address = Address::from_slice(
            &[&**key; 4].concat()[0..StorageKey::ACCOUNT_BYTES],
        );
        address.set_user_account_type_bits();
        let account = Account::new_empty_with_balance(
            &address,
            &DEFAULT_BALANCE.into(),
            &0.into(),
        )
        .unwrap();
        let account_key = StorageKey::new_account_key(&address);
        state_0
            .set(account_key, rlp::encode(&account).into())
            .expect("Failed to set key");
    }

    let epoch_id_0 = H256::default();
    let mut state_root = state_0.compute_state_root().unwrap();
    state_0.commit(epoch_id_0).unwrap();

    println!("Commiting initial {} epochs.", EPOCHS);

    for epoch in 0..EPOCHS {
        state_root = simulate_transactions(
            epoch,
            &state_root,
            &epoch_keys[epoch as usize],
            &state_manager,
            &mut 0,
            &mut 0,
            &mut 0,
            &mut 0,
        );
    }

    println!(
        "Benchmarking last {} epochs with {} transactions",
        EPOCHS,
        EPOCHS as u32 * TXS
    );
    let mut load_ms = 0;
    let mut update_ms = 0;
    let mut write_ms = 0;
    let mut commit_ms = 0;
    for epoch in EPOCHS..EPOCHS * 2 {
        state_root = simulate_transactions(
            epoch,
            &state_root,
            &epoch_keys[epoch as usize],
            &state_manager,
            &mut load_ms,
            &mut update_ms,
            &mut write_ms,
            &mut commit_ms,
        );
    }
    let total_ms = (load_ms + update_ms + write_ms + commit_ms) as f64;
    println!(
        "Benchmark finished, TPS = {}, \
         load = {:.2}%, rlp_and_update = {:.2}%, write = {:.2}%, commit = {:.2}%",
        1000.0 * (TXS as f64) * (EPOCHS as f64) / total_ms,
        100.0 * (load_ms as f64) / total_ms,
        100.0 * (update_ms as f64) / total_ms,
        100.0 * (write_ms as f64) / total_ms,
        100.0 * (commit_ms as f64) / total_ms,
    );
}

fn simulate_transactions(
    epoch: u8, prev_state_root: &StateRootWithAuxInfo, keys: &[&[u8]],
    state_manager: &FakeStateManager, read_ms: &mut u32, update_ms: &mut u32,
    write_ms: &mut u32, commit_ms: &mut u32,
) -> StateRootWithAuxInfo
{
    // Wait for snapshotting to complete. We don't calculate the time spent in
    // making snapshot.
    while state_manager
        .get_storage_manager()
        .in_progress_snapshotting_tasks
        .read()
        .len()
        != 0
    {
        thread::sleep(Duration::from_secs(1));
    }

    let mut addresses = Vec::with_capacity(keys.len());
    for key in keys {
        let mut address = Address::from_slice(
            &[&**key; 4].concat()[0..StorageKey::ACCOUNT_BYTES],
        );
        address.set_user_account_type_bits();
        addresses.push(address);
    }

    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = epoch;
    let mut state = state_manager
        .get_state_for_next_epoch(StateIndex::new_for_next_epoch(
            &epoch_id,
            prev_state_root,
            epoch as u64 + 1,
            state_manager
                .get_storage_manager()
                .get_snapshot_epoch_count(),
        ))
        .unwrap()
        .unwrap();
    let mut values = vec![None; keys.len()];

    let len = keys.len();

    // Load all values.
    let now = Instant::now();
    const PREFETCH: bool = true;
    if PREFETCH {
        const THREADS: usize = 8;
        let mut join_handles = vec![];
        for thread in 0..THREADS {
            let range_start = len * thread / THREADS;
            let range_end = len * (thread + 1) / THREADS;
            let addresses_range = unsafe {
                std::mem::transmute::<&[Address], &'static [Address]>(
                    &addresses[range_start..range_end],
                )
            };
            let value_range = unsafe {
                std::mem::transmute::<
                    &mut [Option<Box<[u8]>>],
                    &'static mut [Option<Box<[u8]>>],
                >(&mut values[range_start..range_end])
            };
            let state_r = unsafe {
                std::mem::transmute::<&State, &'static State>(&state)
            };
            join_handles.push(thread::spawn(move || {
                let mut i = 0;
                for address in addresses_range {
                    value_range[i] = Some(
                        state_r
                            .get(StorageKey::new_account_key(&address))
                            .expect("Failed to get key.")
                            .expect("no such key"),
                    );

                    i += 1;
                }
            }));
        }
        for join_handle in join_handles {
            join_handle.join().unwrap();
        }
    } else {
        let mut i = 0;
        for address in &addresses {
            values[i] = Some(
                state
                    .get(StorageKey::new_account_key(&address))
                    .expect("Failed to get key.")
                    .expect("no such key"),
            );

            i += 1;
        }
    }
    *read_ms += now.elapsed().as_millis() as u32;

    // Update accounts.
    let now = Instant::now();
    for i in 0..len {
        let mut account: primitives::Account = Account::new_from_rlp(
            addresses[i],
            &Rlp::new(&values[i].as_ref().unwrap()),
        )
        .expect("failed to decode rlp");
        if i % 2 == 0 {
            account.balance -= U256::one();
        } else {
            account.balance += U256::one();
        }
        values[i] = Some(rlp::encode(&account).into());
    }
    *update_ms += now.elapsed().as_millis() as u32;

    // Write accounts.
    let now = Instant::now();
    for i in 0..len {
        let key = keys[i];
        let mut address = Address::from_slice(
            &[key; 4].concat()[0..StorageKey::ACCOUNT_BYTES],
        );
        address.set_user_account_type_bits();
        let account_key = StorageKey::new_account_key(&address);

        state
            .set(account_key, values[i].take().unwrap())
            .expect("Failed to set key");
    }
    *write_ms += now.elapsed().as_millis() as u32;

    // Commit.
    let now = Instant::now();
    epoch_id.as_bytes_mut()[0] = epoch + 1;
    let state_root = state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();
    *commit_ms += now.elapsed().as_millis() as u32;

    state_root
}

#[test]
fn test_set_delete() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_unit_test();

    let mut state = state_manager.get_state_for_genesis_write();

    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    let (keys_0, keys_1) = (
        &keys[0..TEST_NUMBER_OF_KEYS / 2],
        &keys[TEST_NUMBER_OF_KEYS / 2..],
    );

    println!("Testing with {} set operations.", keys.len());

    // Insert part 1 and commit.
    for key in keys_0.iter() {
        state
            .set(StorageKey::AccountKey(key), key[..].into())
            .expect("Failed to insert key.");
    }
    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 1;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();

    // In second state, insert part 2, then delete everything.
    let mut state = state_manager
        .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
            &epoch_id,
        ))
        .unwrap()
        .unwrap();
    for key in keys_1.iter() {
        state
            .set(StorageKey::AccountKey(key), key[..].into())
            .expect("Failed to insert key.");
    }

    keys.shuffle(&mut rng);

    println!("Testing with {} delete operations.", keys.len());
    for key in &keys {
        let value = state
            .delete_test_only(StorageKey::AccountKey(key))
            .expect("Failed to delete key.")
            .expect("Failed to get key");
        let equal = (&**key).eq(value.as_ref());
        assert_eq!(equal, true);
    }

    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 2;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();
}

#[test]
fn test_set_delete_all() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_unit_test();

    let mut state = state_manager.get_state_for_genesis_write();
    let empty_state_root = state.compute_state_root().unwrap();

    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    let (keys_0, keys_1) = (
        &keys[0..TEST_NUMBER_OF_KEYS / 2],
        &keys[TEST_NUMBER_OF_KEYS / 2..],
    );

    println!("Testing with {} set operations.", keys.len());

    // Insert part 1 and commit.
    for key in keys_0.iter() {
        state
            .set(
                StorageKey::AccountKey(
                    vec![&key[..], &key[..]].concat().as_slice(),
                ),
                key[..].into(),
            )
            .expect("Failed to insert key.");
    }
    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 1;
    state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();

    // In second state, insert part 2, then delete everything.
    let mut state = state_manager
        .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
            &epoch_id,
        ))
        .unwrap()
        .unwrap();
    for key in keys_1.iter() {
        state
            .set(
                StorageKey::AccountKey(
                    vec![&key[..], &key[..]].concat().as_slice(),
                ),
                key[..].into(),
            )
            .expect("Failed to insert key.");
    }

    keys.shuffle(&mut rng);

    println!("Testing with {} delete_all operations.", keys.len());
    let mut values = Vec::with_capacity(keys.len());
    for key in &keys {
        let key_prefix = &key[0..(2 + rng.gen::<usize>() % 2)];

        let value = state
            .delete_all::<access_mode::Write>(StorageKey::AccountKey(
                key_prefix,
            ))
            .expect("Failed to delete key.");
        if value.is_none() {
            continue;
        }
        let mut value = value.unwrap();
        for (deleted_key, deleted_value) in &value {
            assert_eq!(key_prefix, &deleted_key[0..key_prefix.len()]);
            assert_eq!(deleted_key, &vec![deleted_value.as_ref(); 2].concat());
        }

        for item in value.drain(..) {
            values.push(item);
        }

        let value = state
            .delete_all::<access_mode::Write>(StorageKey::AccountKey(key))
            .expect("Failed to delete key.");
        assert_eq!(value, None);
    }

    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 2;
    let state_root = state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();

    assert_eq!(values.len(), keys.len());
    assert_eq!(state_root, empty_state_root);
}

#[test]
fn test_set_order() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_unit_test();
    let keys: Vec<Vec<u8>> = generate_keys(500000)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();

    let mut epoch_id = H256::default();
    let mut state_0 = state_manager.get_state_for_genesis_write();
    println!("Setting state_0 with {} keys.", keys.len());
    for key in &keys {
        let key_slice = &key[..];
        let actual_key = vec![key_slice; 3].concat();
        let actual_value = vec![key_slice; 1 + (key[0] % 21) as usize].concat();
        state_0
            .set(StorageKey::AccountKey(&actual_key), actual_value.into())
            .expect("Failed to insert key.");
    }
    let _merkle_0 = state_0.compute_state_root().unwrap();
    epoch_id.as_bytes_mut()[0] = 1;
    state_0.commit(epoch_id).unwrap();

    let mut state_1 = state_manager.get_state_for_genesis_write();
    println!("Setting state_1 with {} keys.", keys.len());
    for key in &keys {
        let key_slice = &key[..];
        let actual_key = vec![key_slice; 3].concat();
        let actual_value = vec![key_slice; 1 + (key[0] % 32) as usize].concat();
        state_1
            .set(StorageKey::AccountKey(&actual_key), actual_value.into())
            .expect("Failed to insert key.");
    }
    let merkle_1 = state_1.compute_state_root().unwrap();
    epoch_id.as_bytes_mut()[0] = 2;
    state_1.commit(epoch_id).unwrap();

    let mut state_2 = state_manager.get_state_for_genesis_write();
    println!("Setting state_2 with {} keys.", keys.len());
    for key in keys.iter().rev() {
        let key_slice = &key[..];
        let actual_key = vec![key_slice; 3].concat();
        let actual_value = vec![key_slice; 1 + (key[0] % 32) as usize].concat();
        state_2
            .set(StorageKey::AccountKey(&actual_key), actual_value.into())
            .expect("Failed to insert key.");
    }
    let merkle_2 = state_2.compute_state_root().unwrap();
    epoch_id.as_bytes_mut()[0] = 3;
    state_2.commit(epoch_id).unwrap();

    assert_eq!(merkle_1, merkle_2);
}

#[test]
fn test_set_order_concurrent() {
    let mut rng = get_rng_for_test();
    let state_manager = new_state_manager_for_unit_test();
    let keys = Arc::new(
        generate_keys(TEST_NUMBER_OF_KEYS / 10)
            .iter()
            .filter(|_| rng.gen_bool(0.5))
            .cloned()
            .collect::<Vec<_>>(),
    );

    let mut epoch_id = H256::default();
    let mut state_0 = state_manager.get_state_for_genesis_write();
    println!("Setting state_0 with {} keys.", keys.len());
    for key in keys.iter() {
        let key_slice = &key[..];
        let actual_key = vec![key_slice; 3].concat();
        let actual_value = vec![key_slice; 1 + (key[0] % 21) as usize].concat();
        state_0
            .set(StorageKey::AccountKey(&actual_key), actual_value.into())
            .expect("Failed to insert key.");
    }
    let _merkle_0 = state_0.compute_state_root().unwrap();
    epoch_id.as_bytes_mut()[0] = 1;
    state_0.commit(epoch_id).unwrap();

    let parent_epoch_0 = epoch_id;

    let mut state_1 = state_manager
        .get_state_for_next_epoch(StateIndex::new_for_test_only_delta_mpt(
            &parent_epoch_0,
        ))
        .unwrap()
        .unwrap();
    println!("Setting state_1 with {} keys.", keys.len());
    for key in keys.iter() {
        let key_slice = &key[..];
        let actual_key = vec![key_slice; 3].concat();
        let actual_value = vec![key_slice; 1 + (key[0] % 32) as usize].concat();
        state_1
            .set(StorageKey::AccountKey(&actual_key), actual_value.into())
            .expect("Failed to insert key.");
    }
    let merkle_1 = state_1.compute_state_root().unwrap();
    epoch_id.as_bytes_mut()[0] = 2;
    state_1.commit(epoch_id).unwrap();

    let thread_count = if cfg!(debug_assertions) {
        // Debug build. Fewer threads.
        10
    } else {
        // Release build.
        500
    };
    let mut threads = Vec::with_capacity(thread_count);
    for thread_id in 0..thread_count {
        thread::sleep_ms(30);
        let keys = keys.clone();
        let state_manager = state_manager.clone();
        let merkle_1 = merkle_1.clone();
        threads.push(thread::spawn(move || {
            let mut state_2 = state_manager
                .get_state_for_next_epoch(
                    StateIndex::new_for_test_only_delta_mpt(&parent_epoch_0),
                )
                .unwrap()
                .unwrap();
            //            println!(
            //                "Setting state_{} with {} keys.",
            //                2 + thread_id,
            //                keys.len()
            //            );
            for key in keys.iter().rev() {
                let key_slice = &key[..];
                let actual_key = vec![key_slice; 3].concat();
                let actual_value =
                    vec![key_slice; 1 + (key[0] % 32) as usize].concat();
                state_2
                    .set(
                        StorageKey::AccountKey(&actual_key),
                        actual_value.into(),
                    )
                    .expect("Failed to insert key.");
            }
            let merkle_2 = state_2.compute_state_root().unwrap();
            epoch_id.as_bytes_mut()[0] = ((3 + thread_id) % 256) as u8;
            epoch_id.as_bytes_mut()[1] = ((3 + thread_id) / 256) as u8;
            state_2.commit(epoch_id).unwrap();

            assert_eq!(merkle_1, merkle_2);
        }));
    }
    {
        let mut thread_id = 0;
        for thread in threads.drain(..) {
            thread
                .join()
                .expect(&format!("Thread {} failed.", thread_id));
            thread_id += 1;
        }
    }
}

use crate::{
    state::*,
    state_manager::*,
    tests::{
        generate_keys, get_rng_for_test, new_state_manager_for_unit_test,
        FakeStateManager, TEST_NUMBER_OF_KEYS,
    },
    utils::access_mode,
    StateRootWithAuxInfo,
};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use primitives::{Account, StorageKey};
use rand::{
    distributions::{Distribution, Uniform},
    seq::SliceRandom,
    Rng,
};
use rlp::Rlp;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
