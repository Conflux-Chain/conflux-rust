// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

const DB_PATH: &'static str = "unspecified";

#[test]
fn check_snapshot_mpt_integrity() {
    if DB_PATH == "unspecified" {
        return;
    }
    let db_path = Path::new(DB_PATH);
    let snapshot_db =
        open_snapshot_db_for_testing(db_path, /* readonly = */ true).unwrap();
    let mut key_value_iter = snapshot_db.snapshot_kv_iterator().unwrap().take();
    let total_kvs = check_key_value_load(
        &snapshot_db,
        key_value_iter.iter_range(&[], None).unwrap().take(),
        /* check_value = */ true,
    )
    .unwrap();
    println!("verified {} key values", total_kvs);
}

#[test]
fn check_snapshot_mpt_root() {
    if DB_PATH == "unspecified" {
        return;
    }
    let db_path = Path::new(DB_PATH);
    let snapshot_db =
        open_snapshot_db_for_testing(db_path, /* readonly = */ true).unwrap();
    let mut key_value_iter = snapshot_db.snapshot_kv_iterator().unwrap().take();
    let mut kv_iter = key_value_iter.iter_range(&[], None).unwrap().take();

    let merkle_root =
        (&snapshot_db.open_snapshot_mpt_shared().unwrap()).get_merkle_root();

    let mut mpt_kvs = vec![];
    while let Ok(Some((key, value))) = kv_iter.next() {
        if value.len() == 0 {
            println!("snapshot db value can't be 0");
            assert!(false);
        }
        mpt_kvs.push((key, value));
    }

    let mut new_mpt = FakeSnapshotMptDb::new_discard_write();
    let new_merkle_root = MptMerger::new(None, &mut new_mpt)
        .merge(&DumpedMptKvIterator { kv: mpt_kvs })
        .unwrap();

    assert_eq!(merkle_root, new_merkle_root);
}

pub struct MptIter<'a> {
    cursor: MptCursor<
        &'a mut dyn SnapshotMptTraitRead,
        BasicPathNode<&'a mut dyn SnapshotMptTraitRead>,
    >,
}

impl<'a> MptIter<'a> {
    pub fn new(mpt: &'a mut dyn SnapshotMptTraitRead) -> Result<Self> {
        let mut cursor = MptCursor::new(mpt);
        cursor.load_root()?;
        Ok(Self { cursor })
    }

    pub fn get_key_value(&self) -> Option<(&[u8], &[u8])> {
        let last_node = self.cursor.get_path_nodes().last().unwrap();
        let key = last_node.get_path_to_node().path_slice();
        if key.len() == 0 {
            None
        } else {
            let value = last_node.value_as_slice().unwrap();
            Some((key, value))
        }
    }

    pub fn advance(&mut self) -> Result<()> {
        loop {
            let current_node = self.cursor.current_node_mut();
            let mut down = false;
            for (this_child_index, &SubtreeMerkleWithSize { .. }) in
                current_node
                    .trie_node
                    .get_children_table_ref()
                    .iter()
                    .set_start_index(current_node.next_child_index)
            {
                let child_node = unsafe {
                    // Mute Rust borrow checker because there is no way
                    // around. It's actually safe to open_child_index while
                    // we immutably borrows the trie_node, because
                    // open_child_index won't modify
                    // trie_node.
                    &mut *(current_node
                        as *const BasicPathNode<
                            &'a mut dyn SnapshotMptTraitRead,
                        >
                        as *mut BasicPathNode<&'a mut dyn SnapshotMptTraitRead>)
                }
                .open_child_index(this_child_index)?
                // Unwrap is fine because the child is guaranteed to exist.
                .unwrap();

                drop(current_node);
                down = true;
                self.cursor.push_node(child_node);
                break;
            }

            if down {
                if self.cursor.current_node_mut().has_value() {
                    return Ok(());
                }
            }
            // Pop-up when all children are visited.
            else if self.cursor.get_path_nodes().len() > 1 {
                self.cursor.pop_one_node()?;
            } else {
                break;
            }
        }
        Ok(())
    }
}

pub fn verify_snapshot_db<
    SnapshotDbType: SnapshotDbTrait<ValueType = Box<[u8]>>,
>(
    snapshot_db: &SnapshotDbType,
)
/*
The ugly impl if we don't use Wrap:
We must have snapshot_db: &'db ... in the argument, then the where clause.

where <SnapshotDbType as SnapshotKvIterTrait<'db>>::SnapshotKvIterType:
for<'a> KeyValueDbIterableTrait<'a, MptKeyValue, Error, [u8]>
 */
// Rust compiler should improve so that we don't have to write this completely
// redundant where clause.
where KvdbIterIterator<
        MptKeyValue,
        [u8],
        SnapshotDbType::SnapshotKvdbIterTraitTag,
    >: WrappedTrait<dyn FallibleIterator<Item = MptKeyValue, Error = Error>> {
    let mut mpt_kvs: Vec<MptKeyValue> = vec![];
    let mut key_value_iter = snapshot_db.snapshot_kv_iterator().unwrap().take();
    let mut kv_iter = key_value_iter
        .to_constrain_object_mut()
        .iter_range(&[], None)
        .unwrap()
        .take();

    let kv_iter = kv_iter.to_constrain_object_mut();
    while let Some((key, value)) = kv_iter.next().unwrap() {
        if value.len() == 0 {
            println!("snapshot db value can't be 0");
            assert!(false);
        }
        mpt_kvs.push((key, value));
    }
    drop(kv_iter);

    let mut mpt = snapshot_db.open_snapshot_mpt_shared().unwrap();
    let mut mpt_iter = MptIter::new(&mut mpt).unwrap();
    let mut count = 0;
    for (expected_key, expected_value) in &mpt_kvs {
        count += 1;
        if count % 10000 == 0 {
            println!("verified {} key values.", count);
        }
        loop {
            mpt_iter.advance().unwrap();
            let (key, value) = mpt_iter.get_key_value().unwrap();
            if key.eq(&**expected_key) && value.eq(&**expected_value) {
                break;
            } else {
                println!(
                    "got ({:?}, {:?}), expected ({:?}, {:?})",
                    key, value, expected_key, expected_value
                );
            }
        }
    }
    mpt_iter.advance().unwrap();
    let no_more_key_value = mpt_iter.get_key_value();
    assert_eq!(no_more_key_value, None);
}

#[test]
fn check_snapshot_mpt_by_iter() {
    if DB_PATH == "unspecified" {
        return;
    }
    let db_path = Path::new(DB_PATH);
    let snapshot_db =
        open_snapshot_db_for_testing(db_path, /* readonly = */ true).unwrap();
    verify_snapshot_db(&snapshot_db)
}

use crate::{
    impls::{
        errors::*,
        merkle_patricia_trie::{mpt_cursor::*, MptMerger, *},
        storage_db::snapshot_db_sqlite::test_lib::{
            check_key_value_load, open_snapshot_db_for_testing,
        },
    },
    storage_db::{
        key_value_db::KeyValueDbIterableTrait,
        snapshot_mpt::{SnapshotMptTraitRead, SubtreeMerkleWithSize},
        KvdbIterIterator, OpenSnapshotMptTrait, SnapshotDbTrait,
    },
    tests::{DumpedMptKvIterator, FakeSnapshotMptDb},
    utils::{tuple::ElementSatisfy, wrap::WrappedTrait},
};
use fallible_iterator::FallibleIterator;
use std::path::Path;
