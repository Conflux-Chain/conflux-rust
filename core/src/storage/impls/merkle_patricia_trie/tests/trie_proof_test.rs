// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::{
    trie_proof::TrieProofNode, CompressedPathRaw, CompressedPathTrait,
    TrieNodeTrait, TrieProof, VanillaChildrenTable,
};
use primitives::MERKLE_NULL_NODE;

#[test]
fn test_rlp() {
    let node1 = TrieProofNode::new(
        Default::default(),
        Some(Box::new([0x03, 0x04, 0x05])),
        (&[0x00, 0x01, 0x02][..]).into(),
        /* path_without_first_nibble = */ true,
    );
    assert_eq!(node1, rlp::decode(&rlp::encode(&node1)).unwrap());

    let root_node = {
        let mut children_table = VanillaChildrenTable::default();
        unsafe {
            *children_table.get_child_mut_unchecked(2) = *node1.get_merkle();
            *children_table.get_children_count_mut() = 1;
        }
        TrieProofNode::new(
            children_table,
            None,
            CompressedPathRaw::default(),
            /* path_without_first_nibble = */ false,
        )
    };

    assert_eq!(root_node, rlp::decode(&rlp::encode(&root_node)).unwrap());

    let proof = TrieProof::default();
    assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());

    let nodes = [root_node, node1]
        .iter()
        .cloned()
        .cycle()
        .take(20)
        .collect();
    let proof = TrieProof::new(nodes).unwrap();
    assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
}

#[test]
fn test_proofs() {
    //       ------|path: []|-----
    //      |                     |
    //      |              |path: [0x00, 0x00]|
    //      |                     |
    // |path: [0x20]|   |path: [0x30]            |
    // |val : [0x02]|   |val : [0x00, 0x00, 0x03]|

    let (key1, value1) = ([0x20], [0x02]);
    let (key2, value2) = ([0x00, 0x00, 0x30], [0x00, 0x00, 0x03]);

    let leaf1 = TrieProofNode::new(
        Default::default(),
        Some(Box::new(value1)),
        (&[0x20u8][..]).into(),
        /* path_without_first_nibble = */ true,
    );

    let leaf2 = TrieProofNode::new(
        Default::default(),
        Some(Box::new(value2)),
        (&[0x30u8][..]).into(),
        /* path_without_first_nibble = */ true,
    );

    let ext = {
        let mut children = [MERKLE_NULL_NODE; 16];
        children[0x03] = leaf2.get_merkle().clone();

        TrieProofNode::new(
            children.into(),
            // There must be some value for this node otherwise it contradicts
            // with path compression.
            Some(Default::default()),
            (&[0x00u8, 0x00u8][..]).into(),
            /* path_without_first_nibble = */ true,
        )
    };

    let branch = {
        let mut children = [MERKLE_NULL_NODE; 16];
        children[0x00] = ext.get_merkle().clone();
        children[0x02] = leaf1.get_merkle().clone();

        TrieProofNode::new(
            children.into(),
            None,
            Default::default(),
            /* path_without_first_nibble = */ false,
        )
    };

    let leaf1_hash = leaf1.get_merkle();
    let leaf2_hash = leaf2.get_merkle();
    let ext_hash = ext.get_merkle();
    let branch_hash = branch.get_merkle();
    let root = branch_hash;
    let null = &MERKLE_NULL_NODE;

    // empty proof
    let proof = TrieProof::new(vec![]).unwrap();
    assert!(proof.is_valid_kv(&[0x00], None, null));
    assert!(!proof.is_valid_kv(&[0x00], None, leaf1_hash));
    assert!(!proof.is_valid_kv(&key1, Some(&[0x00]), null));

    // missing node
    let proof = TrieProof::new(vec![branch.clone(), ext.clone()]).unwrap();
    assert!(!proof.is_valid_kv(&key2, Some(&value2), root));

    // wrong hash
    let mut leaf2_wrong = leaf2.clone();
    let mut wrong_merkle = leaf2_wrong.get_merkle().clone();
    wrong_merkle.as_bytes_mut()[0] = 0x00;
    leaf2_wrong.set_merkle(&wrong_merkle);

    let proof = TrieProof::new(vec![
        branch.clone(),
        ext.clone(),
        leaf1.clone(),
        leaf2_wrong,
    ]);
    assert!(proof.is_err());

    // wrong value
    let proof = TrieProof::new(vec![
        branch.clone(),
        ext.clone(),
        leaf1.clone(),
        leaf2.clone(),
    ])
    .unwrap();
    assert!(!proof.is_valid_kv(&key2, Some(&[0x00, 0x00, 0x04]), root));

    // valid proof
    let proof = TrieProof::new(vec![
        branch.clone(),
        ext.clone(),
        leaf1.clone(),
        leaf2.clone(),
    ])
    .unwrap();

    assert!(proof.is_valid_kv(&key1, Some(&value1), root));
    assert!(proof.is_valid_kv(&key2, Some(&value2), root));
    assert!(proof.is_valid_kv(&[0x01], None, root));

    // wrong root
    assert!(!proof.is_valid_kv(&key2, Some(&value2), leaf1_hash));

    // path to `branch` (root)
    let key = &[];
    assert!(proof.is_valid_path_to(key, branch_hash, root));
    assert!(!proof.is_valid_path_to(key, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(key, ext_hash, root));
    assert!(!proof.is_valid_path_to(key, leaf2_hash, root));

    // path to `leaf1`
    let compressed_path_ref = leaf1.compressed_path_ref();
    let path = compressed_path_ref.path_slice();
    assert!(proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, ext_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

    // path to `ext`
    let compressed_path_ref = ext.compressed_path_ref();
    let path = compressed_path_ref.path_slice();
    assert!(proof.is_valid_path_to(path, ext_hash, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

    // path to `leaf2`
    let path = &key2[..];
    assert!(proof.is_valid_path_to(path, leaf2_hash, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, ext_hash, root));

    // non-existent prefix
    let path = &[0x00];
    assert!(proof.is_valid_path_to(path, null, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, ext_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

    // non-existent path
    let path = &[0x10];
    assert!(proof.is_valid_path_to(path, null, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, ext_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

    // non-existent path with existing prefix
    let path = &[0x00, 0x00, 0x30, 0x04];
    assert!(proof.is_valid_path_to(path, null, root));
    assert!(!proof.is_valid_path_to(path, branch_hash, root));
    assert!(!proof.is_valid_path_to(path, ext_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
    assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

    // empty trie
    assert!(proof.is_valid_path_to(&[], null, null));
    assert!(proof.is_valid_path_to(&[0x00], null, null));

    assert!(!proof.is_valid_path_to(&[], branch_hash, null));
    assert!(!proof.is_valid_path_to(&[0x00], branch_hash, null));
}
