// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

fn min_repr_bytes(number_of_keys: usize) -> u8 {
    let mut largest_value = match number_of_keys {
        n if n == 0 => return 0,
        n if n == 1 => return 1,
        n => n - 1,
    };

    let mut min_repr_bytes = 0;

    while largest_value != 0 {
        min_repr_bytes += 1;
        largest_value >>= 8;
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

/// Given an integer-indexed `SimpleMpt` with `num_keys` elements
/// stored in it, convert `key` into the corresponding key format.
pub fn into_simple_mpt_key(key: usize, num_keys: usize) -> Vec<u8> {
    let key_length = min_repr_bytes(num_keys);
    to_index_bytes(key, key_length)
}

pub fn make_simple_mpt(mut values: Vec<Box<[u8]>>) -> SimpleMpt {
    let mut mpt = SimpleMpt::default();
    let keys = values.len();
    let mut mpt_kvs = Vec::with_capacity(keys);

    let index_byte_len = min_repr_bytes(keys);

    for (index, value) in values.drain(..).enumerate() {
        mpt_kvs.push((to_index_bytes(index, index_byte_len), value));
    }

    MptMerger::new(None, &mut mpt)
        .merge(&DumpedMptKvIterator { kv: mpt_kvs })
        .expect("SimpleMpt does not fail.");

    mpt
}

pub fn simple_mpt_merkle_root(simple_mpt: &mut SimpleMpt) -> MerkleHash {
    let maybe_root_node = simple_mpt
        .load_node(&CompressedPathRaw::default())
        .expect("SimpleMpt does not fail.");
    match maybe_root_node {
        None => MERKLE_NULL_NODE,
        Some(root_node) => {
            // if all keys share the same prefix (e.g. 0x00, ..., 0x0f share
            // the first nibble) then they will all be under the first child of
            // the root. in this case, we will use this first child as the root.
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

                root_node.get_child(0).expect("Child 0 must exist").merkle
            } else {
                trace!("debug receipts calculation: root node {:?}", root_node);
                *root_node.get_merkle()
            }
        }
    }
}

pub fn simple_mpt_proof(
    simple_mpt: &mut SimpleMpt, access_key: &[u8],
) -> TrieProof {
    let mut cursor = MptCursor::<
        &mut dyn SnapshotMptTraitRead,
        BasicPathNode<&mut dyn SnapshotMptTraitRead>,
    >::new(simple_mpt);

    cursor.load_root().expect("load_root should succeed");

    // see comment in `simple_mpt_merkle_root`
    let remove_root = cursor.current_node_mut().get_children_count() == 1;

    cursor
        .open_path_for_key::<access_mode::Read>(access_key)
        .expect("open_path_for_key should succeed");

    let mut proof = cursor.to_proof();
    cursor.finish().expect("finish should succeed");

    if remove_root {
        proof = TrieProof::new(proof.get_proof_nodes()[1..].to_vec())
            .expect("Proof with root removed is still connected");
    }

    proof
}

use crate::storage::{
    impls::merkle_patricia_trie::{
        mpt_cursor::{BasicPathNode, MptCursor},
        trie_node::TrieNodeTrait,
        walk::{access_mode, GetChildTrait},
        CompressedPathRaw, MptMerger, TrieProof,
    },
    storage_db::SnapshotMptTraitRead,
    tests::DumpedMptKvIterator,
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};

pub use crate::storage::tests::FakeSnapshotMptDb as SimpleMpt;

#[cfg(test)]
mod tests {
    use super::{
        into_simple_mpt_key, make_simple_mpt, min_repr_bytes,
        simple_mpt_merkle_root, simple_mpt_proof, MerkleHash,
    };

    #[test]
    fn test_min_repr_bytes() {
        assert_eq!(min_repr_bytes(0x00_00_00_00), 0); // 0

        assert_eq!(min_repr_bytes(0x00_00_00_01), 1); // 1
        assert_eq!(min_repr_bytes(0x00_00_01_00), 1); // 256

        assert_eq!(min_repr_bytes(0x00_00_01_01), 2); // 257
        assert_eq!(min_repr_bytes(0x00_01_00_00), 2); // 65536

        assert_eq!(min_repr_bytes(0x00_01_00_01), 3); // 65537
        assert_eq!(min_repr_bytes(0x01_00_00_00), 3); // 16777216
    }

    #[test]
    fn test_into_simple_mpt_key() {
        assert_eq!(into_simple_mpt_key(0x01, 1), vec![0x01]);
        assert_eq!(into_simple_mpt_key(0x01, 256), vec![0x01]);
        assert_eq!(into_simple_mpt_key(0x01, 257), vec![0x01, 0x00]);
        assert_eq!(into_simple_mpt_key(0x01, 65536), vec![0x01, 0x00]);
        assert_eq!(into_simple_mpt_key(0x01, 65537), vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_empty_simple_mpt() {
        let mut mpt = make_simple_mpt(vec![]);
        let root = simple_mpt_merkle_root(&mut mpt);

        assert_eq!(
            root,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                .parse::<MerkleHash>()
                .unwrap()
        );
    }

    fn check_proofs(num_items: usize, proof_size: Vec<usize>) {
        // create k-v pairs:
        // (0x00, 0x00)
        // (0x01, 0x01)
        // ...

        let value_from_key = |key| into_simple_mpt_key(key, num_items);

        let values: Vec<Box<[u8]>> = (0..num_items)
            .map(|k| value_from_key(k).into_boxed_slice())
            .collect();

        let mut mpt = make_simple_mpt(values);
        let root = simple_mpt_merkle_root(&mut mpt);

        for k in 0..num_items {
            let key = into_simple_mpt_key(k, num_items);
            let proof = simple_mpt_proof(&mut mpt, &key);

            assert!(proof_size.contains(&proof.get_proof_nodes().len()));

            // proof should be able to verify correct k-v
            assert!(proof.is_valid_kv(
                &into_simple_mpt_key(k, num_items),
                Some(&value_from_key(k)[..]),
                &root
            ));

            // proof with incorrect value should fail
            assert!(!proof.is_valid_kv(
                &into_simple_mpt_key(k, num_items),
                Some(&value_from_key(k + 1)[..]),
                &root
            ));

            // proof should not be able to verify other values in the trie
            for other in 0..num_items {
                if k == other {
                    continue;
                }

                assert!(!proof.is_valid_kv(
                    &into_simple_mpt_key(other, num_items),
                    Some(&value_from_key(other)[..]),
                    &root
                ));
            }
        }
    }

    #[test]
    #[rustfmt::skip]
    fn test_simple_mpt_proof() {
        // number of items: 0x01
        // keys: 0x00
        // proof size: 1 (root)
        check_proofs(0x01, vec![1]);

        // number of items: 0x02
        // keys: 0x00, 0x01
        //          ^     ^
        // proof size: 2 (root + 2nd nibble)
        check_proofs(0x02, vec![2]);

        // number of items: 0x10
        // keys: 0x00, 0x01, ..., 0x0f
        //          ^     ^          ^
        // proof size: 2 (root + 2nd nibble)
        check_proofs(0x10, vec![2]);

        // number of items: 0x11
        // keys: 0x00, 0x01, ..., 0x0f, 0x10
        // proof size:
        //   0x00, 0x01, ..., 0x0f -> 3 (root + 1st nibble + 2nd nibble)
        //     ^^    ^^         ^^
        //   0x10                  -> 2 (root + 1st nibble)
        //     ^
        check_proofs(0x11, vec![2, 3]);

        // number of items: 0x12
        // keys: 0x00, 0x01, ..., 0x0f, 0x10, 0x11
        //         ^^    ^^         ^^    ^^    ^^
        // proof size: 3 (root + 1st nibble + 2nd nibble)
        check_proofs(0x12, vec![3]);

        // number of items: 0x0100
        // keys: 0x00, 0x01, ..., 0xff
        //         ^^    ^^         ^^
        // proof size: 3 (root + 1st nibble + 2nd nibble)
        check_proofs(0x0100, vec![3]);

        // number of items: 0x101
        // keys: [0x00, 0x00], [0x01, 0x00], [0x02, 0x00], ..., [0x00, 0x01] (little-endian)
        // proof size:
        //   [0x01, 0x00], ..., [0xff, 0x00] -> 3 (root + 1st nibble + 2nd nibble)
        //      ^^                 ^^
        //   [0x00, 0x00], [0x00, 0x10]      -> 4 (root + 1st nibble [=0] + 2nd nibble [=0] + 3rd nibble)
        //      ^^    ^       ^^    ^
        check_proofs(0x0101, vec![3, 4]);
    }
}
