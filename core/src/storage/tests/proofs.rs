// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

fn get_invalid_hash(rng: &mut ChaChaRng, mut hash: H256) -> H256 {
    hash.as_bytes_mut()[rng.gen_range(0, 32)] = 0x00;
    hash.as_bytes_mut()[rng.gen_range(0, 32)] = 0x00;
    hash
}

fn get_invalid_state_root(rng: &mut ChaChaRng, root: &StateRoot) -> StateRoot {
    let delta = get_invalid_hash(rng, root.delta_root);
    let intermediate = get_invalid_hash(rng, root.intermediate_delta_root);
    let snapshot = get_invalid_hash(rng, root.snapshot_root);

    StateRoot {
        delta_root: delta,
        intermediate_delta_root: intermediate,
        snapshot_root: snapshot,
    }
}

fn get_invalid_merkle_triplet(
    rng: &mut ChaChaRng, triplet: &NodeMerkleTriplet,
) -> NodeMerkleTriplet {
    NodeMerkleTriplet {
        delta: triplet.delta.map(|h| get_invalid_hash(rng, h)),
        intermediate: triplet.intermediate.map(|h| get_invalid_hash(rng, h)),
        snapshot: triplet.snapshot.map(|h| get_invalid_hash(rng, h)),
    }
}

fn generate_random_state(
    rng: &mut ChaChaRng,
) -> (FakeStateManager, State, StateRoot, Vec<Vec<u8>>) {
    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();

    let mut keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .into_iter()
        .filter(|_| rng.gen_bool(0.1)) // use fewer keys for now so that tests won't run forever
        .collect();

    for key in &keys {
        state
            .set(StorageKey::AccountKey(key), key[..].into())
            .expect("Inserting k-v should succeed");
    }

    let mut epoch_id = H256::default();
    epoch_id.as_bytes_mut()[0] = 1;
    let root = state.compute_state_root().unwrap();
    state.commit(epoch_id).unwrap();

    keys.shuffle(rng);

    (state_manager, state, root.state_root, keys)

    // TODO: test other key types as well, not just AccountKey
    // TODO: insert keys through multiple snapshot periods
}

fn generate_nonexistent_keys(
    rng: &mut ChaChaRng, existing_keys: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    generate_keys(TEST_NUMBER_OF_KEYS)
        .into_iter()
        .filter(|_| rng.gen_bool(0.1)) // use fewer keys for now so that tests won't run forever
        .filter(|k| !existing_keys.contains(k))
        .collect()
}

#[test]
fn test_valid_state_proof_for_existing_key() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key))
            .expect("kv lookup should succeed");

        assert!(value.is_some());

        // validation of valid proof should succeed
        let key = &key.to_vec();
        let value = value.as_ref().map(|b| &**b);
        assert!(proof.is_valid_kv(key, value, root.clone()));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_valid_state_proof_for_nonexistent_key() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);
    let keys = generate_nonexistent_keys(&mut rng, keys);

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key))
            .expect("kv lookup should succeed");

        assert_eq!(value, None);

        // validation of valid proof should succeed
        let key = &key.to_vec();
        assert!(proof.is_valid_kv(key, None, root.clone()));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_invalid_state_proof() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);

    for key in keys {
        let (value, proof) = state
            .get_with_proof(StorageKey::AccountKey(&key))
            .expect("kv lookup should succeed");

        assert!(value.is_some());

        let key = &key.to_vec();
        let value = value.as_ref().map(|b| &**b);

        // checking proof with invalid state root should fail
        let invalid_root = get_invalid_state_root(&mut rng, &root);
        assert!(!proof.is_valid_kv(key, value, invalid_root));

        // checking proof with invalid value should fail
        let invalid_value = Some(&[0x00; 100][..]);
        assert!(!proof.is_valid_kv(key, invalid_value, root.clone()));

        // checking valid existence proof as non-existence proof should fail
        assert!(!proof.is_valid_kv(key, None, root.clone()));
    }
}

#[test]
fn test_valid_node_merkle_proof_for_existing_key() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions(StorageKey::AccountKey(&key), true)
            .expect("node merkle lookup should succeed");

        assert!(
            triplet.delta.is_some()
                || triplet.intermediate.is_some()
                || triplet.snapshot.is_some()
        );

        // validation of valid proof should succeed
        let key = &key.to_vec();

        assert!(proof.is_valid_triplet(
            key,
            triplet.clone(),
            root.clone(),
            None // TODO: use a proper padding here
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_valid_node_merkle_proof_for_nonexistent_key() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);
    let keys = generate_nonexistent_keys(&mut rng, keys);

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions(StorageKey::AccountKey(&key), true)
            .expect("node merkle lookup should succeed");

        assert_eq!(triplet.delta, None);
        assert_eq!(triplet.intermediate, None);
        assert_eq!(triplet.snapshot, None);

        // validation of valid proof should succeed
        let key = &key.to_vec();

        assert!(proof.is_valid_triplet(
            key,
            triplet.clone(),
            root.clone(),
            None // TODO: use a proper padding here
        ));

        // proof should be serializable
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }
}

#[test]
fn test_invalid_node_merkle_proof() {
    let mut rng = get_rng_for_test();
    let (_, state, root, keys) = generate_random_state(&mut rng);

    for key in keys {
        let (triplet, proof) = state
            .get_node_merkle_all_versions(StorageKey::AccountKey(&key), true)
            .expect("node merkle lookup should succeed");

        assert!(
            triplet.delta.is_some()
                || triplet.intermediate.is_some()
                || triplet.snapshot.is_some()
        );

        let key = &key.to_vec();

        // checking proof with invalid state root should fail
        let invalid_root = get_invalid_state_root(&mut rng, &root);

        assert!(!proof.is_valid_triplet(
            key,
            triplet.clone(),
            invalid_root,
            None // TODO: use a proper padding here
        ));

        // checking proof with invalid triplet should fail
        assert!(triplet.delta.is_some());
        let invalid_triplet = get_invalid_merkle_triplet(&mut rng, &triplet);

        assert!(!proof.is_valid_triplet(
            key,
            invalid_triplet,
            root.clone(),
            None // TODO: use a proper padding here
        ));

        // checking valid existence proof as non-existence proof should fail
        let empty_triplet = NodeMerkleTriplet {
            delta: None,
            intermediate: None,
            snapshot: None,
        };

        assert!(!proof.is_valid_triplet(
            key,
            empty_triplet,
            root.clone(),
            None // TODO: use a proper padding here
        ));
    }
}

use super::{
    super::{state::*, state_manager::*},
    generate_keys, get_rng_for_test, new_state_manager_for_unit_test,
};
use crate::storage::tests::{FakeStateManager, TEST_NUMBER_OF_KEYS};
use cfx_types::H256;
use primitives::{NodeMerkleTriplet, StateRoot, StorageKey};
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaChaRng;
