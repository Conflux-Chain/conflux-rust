// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[test]
fn test_node_ref_delta_mpt_compact_encode_decode() {
    let x = NodeRefDeltaMptCompact::new(1234);
    let rlp_bytes = x.rlp_bytes();
    assert_eq!(
        NodeRefDeltaMptCompact::decode(&Rlp::new(rlp_bytes.as_slice()))
            .unwrap(),
        x
    );
}

#[test]
fn test_full_children_table_encode_decode() {
    let mut children_table = ChildrenTableDeltaMpt::default();
    unsafe {
        for i in 0..CHILDREN_COUNT as u8 {
            children_table = ChildrenTableDeltaMpt::insert_child_unchecked(
                children_table.to_ref(),
                i,
                NodeRefDeltaMptCompact::new(i as u32 * 16384),
            );
        }
        children_table.set_child_unchecked(
            11,
            NodeRefDeltaMpt::Committed { db_key: 0 }.into(),
        );
    }
    let rlp_bytes = children_table.to_ref().rlp_bytes();

    let rlp = &Rlp::new(rlp_bytes.as_slice());
    // Assert that the rlp has 16 items.
    assert_eq!(rlp.item_count().unwrap(), 16);

    let rlp_parsed = ChildrenTableManagedDeltaMpt::decode(&rlp).unwrap();
    assert_eq!(children_table, rlp_parsed.into());
}

#[test]
fn test_non_empty_children_table_encode_decode() {
    let mut children_table = ChildrenTableDeltaMpt::default();
    unsafe {
        for i in 0..(CHILDREN_COUNT / 2) as u8 {
            children_table = ChildrenTableDeltaMpt::insert_child_unchecked(
                children_table.to_ref(),
                i,
                NodeRefDeltaMptCompact::new(i as u32 * 16384),
            );
        }
    }
    let rlp_bytes = children_table.to_ref().rlp_bytes();
    let rlp_parsed =
        ChildrenTableManagedDeltaMpt::decode(&Rlp::new(rlp_bytes.as_slice()))
            .unwrap();
    assert_eq!(children_table, rlp_parsed.into());
}

#[test]
fn test_empty_children_table_encode_decode() {
    let empty_children_table: ChildrenTableDeltaMpt = Default::default();
    let rlp_bytes = empty_children_table.to_ref().rlp_bytes();
    let rlp_parsed =
        ChildrenTableManagedDeltaMpt::decode(&Rlp::new(rlp_bytes.as_slice()))
            .unwrap();
    assert_eq!(
        ChildrenTableDeltaMpt::from(rlp_parsed).get_children_count(),
        0
    );
}

#[test]
fn test_trie_node_encode_decode() {
    // Non-empty ChildrenTableDeltaMpt
    let mut children_table = ChildrenTableDeltaMpt::default();
    unsafe {
        for i in 0..(CHILDREN_COUNT / 2) as u8 {
            children_table = ChildrenTableDeltaMpt::insert_child_unchecked(
                children_table.to_ref(),
                i,
                NodeRefDeltaMptCompact::new(i as u32 * 16384),
            );
        }
    }

    // TrieNode without compressed path.
    let x = TrieNode::<CacheAlgoDataDeltaMpt>::new(
        &Default::default(),
        children_table,
        Some(b"asdf".to_vec()),
        Default::default(),
    );
    let rlp_bytes = x.rlp_bytes();
    let rlp_parsed = TrieNode::<CacheAlgoDataDeltaMpt>::decode(&Rlp::new(
        rlp_bytes.as_slice(),
    ))
    .unwrap();

    assert_eq!(rlp_parsed, x);
}

use super::super::{
    super::node_memory_manager::CacheAlgoDataDeltaMpt, children_table::*,
    node_ref::*, *,
};
use rlp::*;
