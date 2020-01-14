// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod slicer;
mod verifier;

#[derive(Default)]
struct FakeSnapshotMptDb {
    db: BTreeMap<Vec<u8>, SnapshotMptNode>,
    in_place_mode: bool,
    already_written: HashSet<Vec<u8>>,
}

impl FakeSnapshotMptDb {
    fn reset(&mut self, in_place_mode: bool) {
        self.in_place_mode = in_place_mode;
        self.already_written.clear();
    }

    fn assert_eq(&self, expected: &Self) {
        assert_eq!(self.db.len(), expected.db.len());

        // Check subtree size.
        for (k, node) in &expected.db {
            let maybe_got_node = self.db.get(k);
            match maybe_got_node {
                None => panic!("key {:?} not found in resulting mpt."),
                Some(got_node) => {
                    for (child_index, child_ref) in
                        node.get_children_table_ref().iter()
                    {
                        match got_node.get_children_table_ref().get_child(child_index) {
                            None => {
                                panic!(
                                    "Child {} not found. Expected\n\t{:?}\n\
                                    got\n\t{:?}\nkey {:?}",
                                    child_index, node, got_node, k,
                                )
                            }
                            Some(got_child_ref) => {
                                assert_eq!(
                                    child_ref.subtree_size, got_child_ref.subtree_size,
                                    "Subtree size of child {} mismatch. Expected\n\t{:?}\n\
                                    got\n\t{:?}\nkey {:?}",
                                    child_index, node, got_node, k,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

struct FakeSnapshotMptDbIter<'a>(
    btree_map::Range<'a, Vec<u8>, SnapshotMptNode>,
);

impl SnapshotMptTraitReadOnly for FakeSnapshotMptDb {
    fn get_merkle_root(&self) -> MerkleHash { unimplemented!() }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        Ok(self.db.get(&mpt_node_path_to_db_key(path)).cloned())
    }

    fn iterate_subtree_trie_nodes_without_root(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait + '_>> {
        let begin_key_excl = mpt_node_path_to_db_key(path);

        let mut end_key_excl = begin_key_excl.clone();
        // The key is non empty. See also comment for compressed_path_to_db_key.
        *end_key_excl.last_mut().unwrap() += 1;

        Ok(Box::new(FakeSnapshotMptDbIter(self.db.range((
            Excluded(begin_key_excl),
            Excluded(end_key_excl),
        )))))
    }
}

impl SnapshotMptTraitSingleWriter for FakeSnapshotMptDb {
    #[allow(unused)]
    fn as_readonly(&mut self) -> &mut dyn SnapshotMptTraitReadOnly { self }

    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        let old_value = self.db.remove(&key);
        if self.in_place_mode {
            assert!(
                old_value.is_some(),
                "Shouldn't delete node {:?} in in-place mode",
                key
            );
        } else {
            panic!("Shouldn't call delete_node in save-as mode. key {:?}", key);
        }
        if self.already_written.contains(&key) {
            panic!("Shouldn't delete a newly written node. key {:?}", key);
        }
        Ok(())
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        self.db.insert(key.clone(), trie_node.clone());
        if !self.already_written.insert(key.clone()) {
            panic!("Shouldn't write a node more than one time. key {:?}", key);
        }
        Ok(())
    }
}

impl FallibleIterator for FakeSnapshotMptDbIter<'_> {
    type Error = Error;
    type Item = (CompressedPathRaw, SnapshotMptNode);

    fn next(&mut self) -> Result<Option<Self::Item>> {
        match self.0.next() {
            Some((k, v)) => {
                Ok(Some((mpt_node_path_from_db_key(k)?, v.clone())))
            }
            None => Ok(None),
        }
    }
}

fn assert_snapshot_mpt_formation(mpt_kv_iter: &DumpedDeltaMptIterator) {
    let snapshot_mpt_nodes;
    let delta_mpt_root = {
        let state_manager = new_state_manager_for_unit_test();
        let mut state = state_manager.get_state_for_genesis_write();
        for (key, value) in &mpt_kv_iter.kv {
            state
                .set(StorageKey::AccountKey(key), value.clone())
                .expect("Failed to insert key.");
        }

        let mut epoch_id = EpochId::default();
        epoch_id.as_bytes_mut()[0] = 1;
        let root = state.compute_state_root().unwrap().state_root;
        state.commit(epoch_id).unwrap();

        snapshot_mpt_nodes =
            state_manager.number_committed_nodes.load(Ordering::Relaxed);

        root.delta_root
    };

    println!(
        "Checking snapshot mpt formation of {} keys with expected \
         merkle_root {:?} and number of nodes {}",
        mpt_kv_iter.kv.len(),
        delta_mpt_root,
        snapshot_mpt_nodes
    );

    let mut empty_snapshot_mpt = FakeSnapshotMptDb::default();
    let mut new_snapshot_mpt = FakeSnapshotMptDb::default();

    // Save-as mode.
    new_snapshot_mpt.reset(/* in_place_mode */ true);
    let snapshot_merkle_root =
        MptMerger::new(Some(&mut empty_snapshot_mpt), &mut new_snapshot_mpt)
            .merge(&mpt_kv_iter)
            .unwrap();
    assert_eq!(delta_mpt_root, snapshot_merkle_root);
    assert_eq!(new_snapshot_mpt.db.len(), snapshot_mpt_nodes);

    empty_snapshot_mpt.reset(/* in_place_mode */ true);
    let snapshot_merkle_root = MptMerger::new(None, &mut empty_snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();
    assert_eq!(delta_mpt_root, snapshot_merkle_root);
    assert_eq!(empty_snapshot_mpt.db.len(), snapshot_mpt_nodes);
}

#[test]
fn test_merkle_root() {
    // Merkle root of empty db.
    assert_snapshot_mpt_formation(&DumpedDeltaMptIterator::default());

    // Merkle root of random set of keys.
    let mut rng = get_rng_for_test();
    for _i in 0..5 {
        let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
            .iter()
            .filter(|_| rng.gen_bool(0.1))
            .cloned()
            .collect();
        let mpt_kv_iter = DumpedDeltaMptIterator {
            kv: keys.iter().map(|k| (k[..].into(), k[..].into())).collect(),
        };
        assert_snapshot_mpt_formation(&mpt_kv_iter);
    }
}

#[test]
fn test_delete_all() {
    let mut rng = get_rng_for_test();
    let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS)
        .iter()
        .filter(|_| rng.gen_bool(0.5))
        .cloned()
        .collect();
    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: keys.iter().map(|k| (k[..].into(), k[..].into())).collect(),
    };

    let mut empty_snapshot_mpt = FakeSnapshotMptDb::default();
    let mut snapshot_mpt = FakeSnapshotMptDb::default();

    // Now snapshot_mpt contains key-values.
    snapshot_mpt.reset(/* in_place_mode */ false);
    MptMerger::new(Some(&mut empty_snapshot_mpt), &mut snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mpt_deleter = DumpedDeltaMptIterator {
        kv: keys
            .iter()
            .map(|k| (k[..].into(), Default::default()))
            .collect(),
    };

    // Save-as mode.
    empty_snapshot_mpt.reset(/* in_place_mode */ false);
    let merkle_root =
        MptMerger::new(Some(&mut snapshot_mpt), &mut empty_snapshot_mpt)
            .merge(&mpt_deleter)
            .unwrap();
    assert_eq!(MERKLE_NULL_NODE, merkle_root);
    assert_eq!(0, empty_snapshot_mpt.db.len());

    // In-place mode
    snapshot_mpt.reset(/* in_place_mode */ true);
    let merkle_root = MptMerger::new(None, &mut snapshot_mpt)
        .merge(&mpt_deleter)
        .unwrap();
    assert_eq!(MERKLE_NULL_NODE, merkle_root);
    assert_eq!(0, snapshot_mpt.db.len());
}

#[test]
fn test_inserts_deletes_and_subtree_size() {
    let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    let set_size = TEST_NUMBER_OF_KEYS / 10;
    let (keys_unchanged, keys_overwritten, keys_delete, keys_new) = (
        &keys[0..set_size],
        &keys[set_size..set_size * 2],
        &keys[set_size * 2..set_size * 3],
        &keys[set_size * 3..set_size * 4],
    );

    // Case 1. Start with a snapshot mpt consisting of keys_delete,
    // Apply the change, then end up with a snapshot mpt consisting of keys_new.
    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: keys_delete
            .iter()
            .map(|k| (k[..].into(), k[..].into()))
            .collect(),
    };

    let mut in_place_mod_mpt = FakeSnapshotMptDb::default();
    MptMerger::new(None, &mut in_place_mod_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: keys_new
            .iter()
            .map(|k| (k[..].into(), k[..].into()))
            .collect(),
    };
    let mut new_snapshot_mpt = FakeSnapshotMptDb::default();
    let supposed_merkle_root = MptMerger::new(None, &mut new_snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let delta_mpt_iter = DumpedDeltaMptIterator {
        kv: [
            keys_delete
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_new
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };
    let mut save_as_mode_mpt = FakeSnapshotMptDb::default();
    let new_merkle_root =
        MptMerger::new(Some(&mut in_place_mod_mpt), &mut save_as_mode_mpt)
            .merge(&delta_mpt_iter)
            .unwrap();
    assert_eq!(new_merkle_root, supposed_merkle_root);
    save_as_mode_mpt.assert_eq(&new_snapshot_mpt);

    in_place_mod_mpt.reset(/* in_place_mode */ true);
    let new_merkle_root = MptMerger::new(None, &mut in_place_mod_mpt)
        .merge(&delta_mpt_iter)
        .unwrap();
    assert_eq!(new_merkle_root, supposed_merkle_root);
    in_place_mod_mpt.assert_eq(&new_snapshot_mpt);

    // Case 2. Start with a snapshot mpt consisting of keys_unchanged,
    // keys_overwritten, keys_delete, Apply the change, then end up with a
    // snapshot mpt consisting of (keys_unchanged, keys_overwritten, keys_new).
    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: [
            keys_unchanged
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_delete
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
            keys_overwritten
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[0..2])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };

    let mut in_place_mod_mpt = FakeSnapshotMptDb::default();
    MptMerger::new(None, &mut in_place_mod_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: [
            keys_unchanged
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_new
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
            keys_overwritten
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };
    let mut new_snapshot_mpt = FakeSnapshotMptDb::default();
    let supposed_merkle_root = MptMerger::new(None, &mut new_snapshot_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    let delta_mpt_iter = DumpedDeltaMptIterator {
        kv: [
            keys_delete
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_new
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
            keys_overwritten
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };
    let mut save_as_mode_mpt = FakeSnapshotMptDb::default();
    let new_merkle_root =
        MptMerger::new(Some(&mut in_place_mod_mpt), &mut save_as_mode_mpt)
            .merge(&delta_mpt_iter)
            .unwrap();
    assert_eq!(new_merkle_root, supposed_merkle_root);
    save_as_mode_mpt.assert_eq(&new_snapshot_mpt);

    in_place_mod_mpt.reset(/* in_place_mode */ true);
    let new_merkle_root = MptMerger::new(None, &mut in_place_mod_mpt)
        .merge(&delta_mpt_iter)
        .unwrap();
    assert_eq!(new_merkle_root, supposed_merkle_root);
    in_place_mod_mpt.assert_eq(&new_snapshot_mpt);
}

#[test]
fn test_two_way_merge() {
    let keys: Vec<Vec<u8>> = generate_keys(TEST_NUMBER_OF_KEYS);
    let set_size = TEST_NUMBER_OF_KEYS / 10;
    let (keys_unchanged, keys_overwritten, keys_delete, keys_new) = (
        &keys[0..set_size],
        &keys[set_size..set_size * 2],
        &keys[set_size * 2..set_size * 3],
        &keys[set_size * 3..set_size * 4],
    );

    let mpt_kv_iter = DumpedDeltaMptIterator {
        kv: [
            keys_unchanged
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_delete
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
            keys_overwritten
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[0..2])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };

    let mut in_place_mod_mpt = FakeSnapshotMptDb::default();
    MptMerger::new(None, &mut in_place_mod_mpt)
        .merge(&mpt_kv_iter)
        .unwrap();

    // One way merge.
    let delta_mpt_iter = DumpedDeltaMptIterator {
        kv: [
            keys_delete
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::default()))
                .collect::<Vec<_>>(),
            keys_new
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
            keys_overwritten
                .iter()
                .map(|k| (Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..])))
                .collect::<Vec<_>>(),
        ]
        .concat(),
    };
    let mut save_as_mode_mpt = FakeSnapshotMptDb::default();
    let supposed_merkle_root =
        MptMerger::new(Some(&mut in_place_mod_mpt), &mut save_as_mode_mpt)
            .merge(&delta_mpt_iter)
            .unwrap();

    // Two way merge.
    in_place_mod_mpt.reset(/* in_place_mode */ true);
    let mut keys_deletion = Vec::from(keys_delete);
    keys_deletion.sort();
    let deletion = keys_deletion
        .iter()
        .map(|k| Ok(Vec::<u8>::from(&k[..])))
        .collect::<Vec<_>>();
    let mut keys_insertion = [keys_new, keys_overwritten].concat();
    keys_insertion.sort();
    let insertion = keys_insertion
        .iter()
        .map(|k| Ok((Vec::<u8>::from(&k[..]), Box::<[u8]>::from(&k[..]))))
        .collect::<Vec<_>>();

    let new_merkle_root = MptMerger::new(None, &mut in_place_mod_mpt)
        .merge_insertion_deletion_separated(
            fallible_iterator::convert(deletion.into_iter()),
            fallible_iterator::convert(insertion.into_iter()),
        )
        .unwrap();

    // Merge result should be the same.
    assert_eq!(new_merkle_root, supposed_merkle_root);
    in_place_mod_mpt.assert_eq(&save_as_mode_mpt);
}

#[allow(unused)]
fn test_delta_subtree_size() {
    // FIXME: complete this test.
    unimplemented!()
}

use crate::storage::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            CompressedPathRaw, CompressedPathTrait, MptMerger, TrieNodeTrait,
        },
        storage_db::snapshot_mpt::{
            mpt_node_path_from_db_key, mpt_node_path_to_db_key,
        },
    },
    state::StateTrait,
    state_manager::StateManagerTrait,
    storage_db::{
        SnapshotMptIteraterTrait, SnapshotMptNode, SnapshotMptTraitReadOnly,
        SnapshotMptTraitSingleWriter,
    },
    tests::{
        generate_keys, get_rng_for_test, new_state_manager_for_unit_test,
        DumpedDeltaMptIterator, TEST_NUMBER_OF_KEYS,
    },
};
use fallible_iterator::FallibleIterator;
use primitives::{EpochId, MerkleHash, StorageKey, MERKLE_NULL_NODE};
use rand::Rng;
use std::{
    collections::{btree_map, BTreeMap, HashSet},
    ops::Bound::Excluded,
    sync::atomic::Ordering,
};
