// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

fn min_repr_bytes(mut number_of_keys: usize) -> u8 {
    let mut min_repr_bytes = 0;
    while number_of_keys != 0 {
        min_repr_bytes += 1;
        number_of_keys >>= 8;
    }

    min_repr_bytes
}

fn to_index_bytes(mut index: usize, len: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; len as usize];
    for i in 0..(len as usize) {
        bytes[i] = index as u8;
        index >>= 8;
    }

    bytes
}

pub fn make_simple_mpt(mut values: Vec<Box<[u8]>>) -> FakeSnapshotMptDb {
    let mut mpt = FakeSnapshotMptDb::default();
    let keys = values.len();
    let mut mpt_kvs = Vec::with_capacity(keys);

    let index_byte_len = min_repr_bytes(keys);
    for (index, value) in values.drain(..).enumerate() {
        mpt_kvs.push((to_index_bytes(index, index_byte_len), value));
    }

    MptMerger::new(None, &mut mpt)
        .merge(&DumpedMptKvIterator { kv: mpt_kvs })
        // FakeSnapshotMptDb does not fail.
        .unwrap();

    mpt
}

pub fn simple_mpt_merkle_root(
    simple_mpt: &mut FakeSnapshotMptDb,
) -> MerkleHash {
    let maybe_root_node = simple_mpt
        .load_node(&CompressedPathRaw::default())
        // FakeSnapshotMptDb does not fail.
        .unwrap();
    match maybe_root_node {
        None => MERKLE_NULL_NODE,
        Some(root_node) => {
            if root_node.get_children_count() == 1 {
                trace!(
                    "debug receipts calculation: root node {:?}",
                    simple_mpt.load_node(
                        &CompressedPathRaw::new_and_apply_mask(
                            &[0],
                            CompressedPathRaw::second_nibble_mask()
                        )
                    )
                );
                // The actual root is the root's child 0 because
                // the first nibble for all keys are 0.
                root_node
                    .get_child(0)
                    // Child 0 must exist
                    .unwrap()
                    .merkle
            } else {
                trace!("debug receipts calculation: root node {:?}", root_node);
                *root_node.get_merkle()
            }
        }
    }
}

// FIXME: add tests and verification code with Vec<TrieProofNode>.

use crate::storage::{
    impls::merkle_patricia_trie::{
        trie_node::TrieNodeTrait, walk::GetChildTrait, CompressedPathRaw,
        MptMerger,
    },
    storage_db::SnapshotMptTraitRead,
    tests::{DumpedMptKvIterator, FakeSnapshotMptDb},
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};
