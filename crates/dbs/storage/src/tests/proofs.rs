// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Divide `v` into `n` portions and return the `k`th (starting from 0).
/// ```
/// let x = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
/// assert_eq!(portion(&x, 0, 5), &[1, 2]);
/// assert_eq!(portion(&x, 1, 5), &[3, 4]);
/// assert_eq!(portion(&x, 2, 5), &[5, 6]);
/// assert_eq!(portion(&x, 3, 5), &[7, 8]);
/// assert_eq!(portion(&x, 4, 5), &[9, 10]);
/// ```
fn portion<T>(v: &Vec<T>, k: usize, n: usize) -> &[T] {
    assert!(k < n);
    let from = k * v.len() / n;
    let to = (k + 1) * v.len() / n;
    &v[from..to]
}

// generate state with snapshot, intermediate and delta tries
//                    [snapshot] [intermediate] [delta]
// 1/7 of keys are in     X
// 1/7 of keys are in     X            X
// 1/7 of keys are in     X                        X
// 1/7 of keys are in     X            X           X
// 1/7 of keys are in                  X
// 1/7 of keys are in                  X           X
// 1/7 of keys are in                              X
fn generate_random_state(
    rng: &mut ChaChaRng,
) -> (FakeStateManager, State, DeltaMptKeyPadding, Vec<Vec<u8>>) {
    let snapshot_epoch_count = 1;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );

    // TODO: test other key types as well, not just AccountKey

    let mut keys: Vec<Vec<u8>> = generate_account_keys(TEST_NUMBER_OF_KEYS)
        .into_iter()
        .filter(|_| rng.gen_bool(0.2))
        .collect();

    // insert 0th, 1st, 2nd, 3rd 1/7 portions into state-0
    let mut state_0 = state_manager.get_state_for_genesis_write();

    for key in portion(&keys, 0, 7) {
        state_0
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 1, 7) {
        state_0
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 2, 7) {
        state_0
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 3, 7) {
        state_0
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    let mut epoch_id_0 = H256::default();
    epoch_id_0.as_bytes_mut()[0] = 1;
    let root_0 = state_0.compute_state_root().unwrap();
    state_0.commit(epoch_id_0).unwrap();

    // insert 1st, 3rd, 4th, 5th 1/7 portions into state-1
    let mut state_1 = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_id_0,
                &root_0,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();

    for key in portion(&keys, 1, 7) {
        state_1
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 3, 7) {
        state_1
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 4, 7) {
        state_1
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 5, 7) {
        state_1
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    let mut epoch_id_1 = H256::default();
    epoch_id_1.as_bytes_mut()[0] = 2;
    let root_1 = state_1.compute_state_root().unwrap();
    state_1.commit(epoch_id_1).unwrap();

    // insert 2nd, 3rd, 5th, 6th 1/7 portions into state-2
    let mut state_2 = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_id_1,
                &root_1,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();

    for key in portion(&keys, 2, 7) {
        state_2
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 3, 7) {
        state_2
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 5, 7) {
        state_2
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    for key in portion(&keys, 6, 7) {
        state_2
            .set(
                StorageKey::AccountKey(key).with_native_space(),
                key[..].into(),
            )
            .expect("Inserting k-v should succeed");
    }

    let mut epoch_id_2 = H256::default();
    epoch_id_2.as_bytes_mut()[0] = 3;
    let root_2 = state_2.compute_state_root().unwrap();
    state_2.commit(epoch_id_2).unwrap();

    keys.shuffle(rng);

    let intermediate_padding = StorageKeyWithSpace::delta_mpt_padding(
        &root_2.state_root.snapshot_root,
        &root_2.state_root.intermediate_delta_root,
    );

    let new_state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_id_2,
                &root_2,
                3,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();

    (state_manager, new_state, intermediate_padding, keys)
}

fn select_keys(
    rng: &mut ChaChaRng, existing_keys: &Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    existing_keys
        .iter()
        .filter(|_| rng.gen_bool(0.1))
        .cloned()
        .collect()
}

fn generate_nonexistent_keys(
    rng: &mut ChaChaRng, existing_keys: &Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    generate_account_keys(TEST_NUMBER_OF_KEYS)
        .into_iter()
        .filter(|_| rng.gen_bool(0.1)) // use fewer keys for now so that tests won't run forever
        .filter(|k| !existing_keys.contains(k))
        .collect()
}

fn get_invalid_hash(rng: &mut ChaChaRng, hash: H256) -> H256 {
    let mut new_hash = hash;

    while new_hash == hash {
        new_hash.as_bytes_mut()[rng.random_range(0..32)] = rng.gen::<u8>();
    }

    new_hash
}

fn get_invalid_maybe_hash(
    rng: &mut ChaChaRng, maybe_hash: Option<H256>,
) -> Option<H256> {
    // randomly mutate hash
    let mut new_maybe_hash = maybe_hash.map(|h| get_invalid_hash(rng, h));

    // randomly change Some(_) to None
    if rng.gen_bool(0.1) {
        new_maybe_hash = None;
    }

    new_maybe_hash
}

fn opt_to_bin<T>(opt: &Option<T>) -> usize {
    match opt {
        None => 0,
        Some(_) => 1,
    }
}

fn get_invalid_state_root(
    rng: &mut ChaChaRng, mut root: StateRoot, num_proofs: usize,
) -> StateRoot {
    // num_proofs: if only one proof is provided (i.e. the value is in the delta
    // trie), we only mutate the delta root. if two or three were provided, we
    // randomly mutate one of the corresponding roots.

    match rng.random_range(0..num_proofs) {
        0 => root.delta_root = get_invalid_hash(rng, root.delta_root),
        1 => {
            root.intermediate_delta_root =
                get_invalid_hash(rng, root.intermediate_delta_root)
        }
        2 => root.snapshot_root = get_invalid_hash(rng, root.snapshot_root),
        _ => assert!(false, "Unexpected random number"),
    }

    root
}

fn get_invalid_merkle_triplet(
    rng: &mut ChaChaRng, triplet: &NodeMerkleTriplet,
) -> NodeMerkleTriplet {
    NodeMerkleTriplet {
        delta: get_invalid_maybe_hash(rng, triplet.delta.clone().into_option())
            .into(),
        intermediate: get_invalid_maybe_hash(
            rng,
            triplet.intermediate.clone().into_option(),
        )
        .into(),
        snapshot: get_invalid_maybe_hash(rng, triplet.snapshot),
    }
}

fn get_invalid_delta_padding(
    padding: &DeltaMptKeyPadding,
) -> DeltaMptKeyPadding {
    let mut new_padding = padding.clone();

    // note: we cannot randomly mutate as we only use portion of the padding
    new_padding[0] = 0x00;
    new_padding[1] = 0x00;
    new_padding[2] = 0x00;

    new_padding
}

#[test]
fn test_valid_state_proof_for_existing_key() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key).with_native_space())
            .expect("kv lookup should succeed");

        assert!(value.is_some());

        // validation of valid proof should succeed
        let key = &key.to_vec();
        let value = value.as_ref().map(|b| &**b);
        assert!(proof.is_valid_kv(
            key,
            value,
            root.clone(),
            Some(padding.clone())
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_valid_state_proof_for_nonexistent_key() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;
    let keys = generate_nonexistent_keys(&mut rng, &keys);

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key).with_native_space())
            .expect("kv lookup should succeed");

        assert_eq!(value, None);

        // validation of valid proof should succeed
        let key = &key.to_vec();
        assert!(proof.is_valid_kv(
            key,
            None,
            root.clone(),
            Some(padding.clone())
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_invalid_state_proof() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key).with_native_space())
            .expect("kv lookup should succeed");

        assert!(value.is_some());

        let key = &key.to_vec();
        let value = value.as_ref().map(|b| &**b);

        // checking proof with invalid state root should fail
        let num_proofs = opt_to_bin(&proof.delta_proof)
            + opt_to_bin(&proof.intermediate_proof)
            + opt_to_bin(&proof.snapshot_proof);

        let invalid_root =
            get_invalid_state_root(&mut rng, root.clone(), num_proofs);

        assert!(!proof.is_valid_kv(
            key,
            value,
            invalid_root,
            Some(padding.clone())
        ));

        // checking proof with invalid value should fail
        let invalid_value = Some(&[0x00; 100][..]);
        assert!(!proof.is_valid_kv(
            key,
            invalid_value,
            root.clone(),
            Some(padding.clone())
        ));

        // checking proof with invalid intermediate mpt existence should fail.
        if proof.intermediate_proof.is_some() {
            assert!(!proof.is_valid_kv(key, value, root.clone(), None));

            // Existence proof with invalid padding can be fine when delta proof
            // combined with snapshot proof prove the key-value and the change
            // of intermediate padding results into non-existence key in
            // the intermediate mpt.
            /*
            let invalid_padding = get_invalid_delta_padding(&padding);

            assert!(!proof.is_valid_kv(
                key,
                value,
                root.clone(),
                Some(invalid_padding),
            ));
             */
        }

        // checking valid existence proof as non-existence proof should fail
        assert!(!proof.is_valid_kv(
            key,
            None,
            root.clone(),
            Some(padding.clone())
        ));
    }
}

#[test]
fn test_valid_node_merkle_proof_for_existing_key() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions::<WithProof>(
                StorageKey::AccountKey(&key).with_native_space(),
            )
            .expect("node merkle lookup should succeed");

        assert!(
            triplet.delta.is_some()
                || triplet.intermediate.is_some()
                || triplet.snapshot.is_some()
        );

        // validation of valid proof should succeed
        let key = &key.to_vec();

        assert!(proof.is_valid(
            key,
            &triplet,
            root.clone(),
            Some(padding.clone()),
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_valid_node_merkle_proof_for_nonexistent_key() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;
    let keys = generate_nonexistent_keys(&mut rng, &keys);

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions::<WithProof>(
                StorageKey::AccountKey(&key).with_native_space(),
            )
            .expect("node merkle lookup should succeed");

        assert_eq!(triplet.delta, MptValue::None);
        assert_eq!(triplet.intermediate, MptValue::None);
        assert_eq!(triplet.snapshot, None);

        // validation of valid proof should succeed
        let key = &key.to_vec();

        assert!(proof.is_valid(
            key,
            &triplet,
            root.clone(),
            Some(padding.clone()),
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_invalid_node_merkle_proof() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);
    let root = state.get_state_root().unwrap().state_root;

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions::<WithProof>(
                StorageKey::AccountKey(&key).with_native_space(),
            )
            .expect("node merkle lookup should succeed");

        assert!(
            triplet.delta.is_some()
                || triplet.intermediate.is_some()
                || triplet.snapshot.is_some()
        );

        assert!(
            proof.delta_proof.is_some()
                || proof.intermediate_proof.is_some()
                || proof.snapshot_proof.is_some()
        );

        let key = &key.to_vec();

        // checking proof with invalid state root should fail
        let invalid_root = get_invalid_state_root(&mut rng, root.clone(), 3);

        assert!(!proof.is_valid(
            key,
            &triplet,
            invalid_root,
            Some(padding.clone()),
        ));

        // checking proof with invalid triplet should fail
        let invalid_triplet = get_invalid_merkle_triplet(&mut rng, &triplet);

        assert!(!proof.is_valid(
            key,
            &invalid_triplet,
            root.clone(),
            Some(padding.clone()),
        ));

        // checking proof with invalid padding should fail
        if triplet.intermediate.is_some() {
            let invalid_padding = get_invalid_delta_padding(&padding);

            assert!(!proof.is_valid(
                key,
                &triplet,
                root.clone(),
                Some(invalid_padding),
            ));

            assert!(!proof.is_valid(key, &triplet, root.clone(), None,));
        }

        // checking valid existence proof as non-existence proof should fail
        let empty_triplet = NodeMerkleTriplet {
            delta: MptValue::None,
            intermediate: MptValue::None,
            snapshot: None,
        };

        assert!(!proof.is_valid(
            key,
            &empty_triplet,
            root.clone(),
            Some(padding.clone()),
        ));
    }
}

#[test]
fn test_recording_storage() {
    let mut rng = get_rng_for_test();

    // note: do not drop state_manager (_mgr)
    let (_mgr, state, padding, keys) = generate_random_state(&mut rng);

    let state = RecordingStorage::new(state);
    let root = state.get_state_root().unwrap().state_root;

    let read_some = select_keys(&mut rng, &keys);
    let read_none = generate_nonexistent_keys(&mut rng, &keys);
    let read_all: Vec<_> =
        read_some.iter().chain(read_none.iter()).cloned().collect();

    // lookup keys
    for key in &read_all {
        let _value = state
            .get(StorageKey::AccountKey(key).with_native_space())
            .expect("kv lookup failed");
    }

    // extract proof
    let proof = state.try_into_proof().expect("proof is inconsistent");

    // proof should work for all keys read
    for key in &read_some {
        assert!(proof.is_valid_kv(
            key,
            key[..].into(),
            root.clone(),
            Some(padding.clone())
        ));
    }

    for key in &read_none {
        assert!(proof.is_valid_kv(
            key,
            None,
            root.clone(),
            Some(padding.clone())
        ));
    }

    // proof should not work with incorrect value
    for key in &read_some {
        let mut value = key.clone();
        value[0] = !value[0];

        assert!(!proof.is_valid_kv(
            key,
            value[..].into(),
            root.clone(),
            Some(padding.clone())
        ));

        assert!(!proof.is_valid_kv(
            key,
            None,
            root.clone(),
            Some(padding.clone())
        ));
    }

    for key in &read_none {
        assert!(!proof.is_valid_kv(
            key,
            vec![1][..].into(),
            root.clone(),
            Some(padding.clone())
        ));
    }

    // proof should not work for any other keys
    for key in generate_nonexistent_keys(&mut rng, &read_all) {
        let can_prove = proof.is_valid_kv(
            &key,
            key[..].into(),
            root.clone(),
            Some(padding.clone()),
        );

        // note: a proof might incidentally prove other key-value pairs in the
        // state. for instance, a nonexistence proof for a key might happen to
        // prove the existence of another.

        assert!(!can_prove || keys.contains(&key));
    }
}

use crate::{
    state::*,
    state_manager::*,
    tests::{
        generate_account_keys, get_rng_for_test,
        new_state_manager_for_unit_test_with_snapshot_epoch_count,
        FakeStateManager, TEST_NUMBER_OF_KEYS,
    },
    RecordingStorage,
};
use cfx_types::H256;
use primitives::{
    DeltaMptKeyPadding, MptValue, NodeMerkleTriplet, StateRoot, StorageKey,
    StorageKeyWithSpace,
};
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaChaRng;
