use super::*;
use cfx_minimal_mpt::MptValue;
use cfx_types::U256;

fn h(b: u8) -> H256 {
    H256([b; 32])
}

/// build → save → load → into_parts reproduces every field, including the
/// RLP-encoded receipts window and the reused minimal-mpt snapshot.
#[test]
fn checkpoint_roundtrips_through_disk() {
    let mut mmpt = PersistedState::default();
    mmpt.height = 4000;

    let mut commitments = BTreeMap::new();
    commitments.insert(
        3998u64,
        EpochCommitment {
            state_root: h(1),
            receipts_root: h(2),
            logs_bloom_hash: h(3),
        },
    );
    commitments.insert(
        4000u64,
        EpochCommitment {
            state_root: h(4),
            receipts_root: h(5),
            logs_bloom_hash: h(6),
        },
    );

    let receipts = vec![Arc::new(BlockReceipts {
        receipts: vec![],
        block_number: 12345,
        secondary_reward: U256::from(777u64),
        tx_execution_error_messages: vec!["boom".to_string()],
    })];
    let mut executed = BTreeMap::new();
    executed.insert(
        4000u64,
        ExecutedEpoch {
            blocks: vec![],
            receipts,
        },
    );

    let prev_root = StateRootWithAuxInfo::genesis(&h(9));
    let ckpt = Checkpoint::build(
        mmpt,
        h(7),
        &prev_root,
        Some(111),
        Some(222),
        &commitments,
        &executed,
    );
    assert_eq!(ckpt.height(), 4000);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ckpt.bin");
    ckpt.save(&path).unwrap();
    let loaded = Checkpoint::load(&path).unwrap().unwrap();
    let (
        mmpt2,
        hash2,
        root2,
        pos_view2,
        finalized_epoch2,
        commitments2,
        executed2,
    ) = loaded.into_parts().unwrap();

    assert_eq!(mmpt2.height, 4000);
    assert_eq!(hash2, h(7));
    assert_eq!(root2, prev_root);
    assert_eq!(pos_view2, Some(111));
    assert_eq!(finalized_epoch2, Some(222));
    assert_eq!(commitments2.len(), 2);
    assert_eq!(commitments2[&4000].state_root, h(4));
    assert_eq!(commitments2[&3998].logs_bloom_hash, h(3));

    let r = &executed2[&4000].receipts[0];
    assert_eq!(r.block_number, 12345);
    assert_eq!(r.secondary_reward, U256::from(777u64));
    assert_eq!(r.tx_execution_error_messages, vec!["boom".to_string()]);
}

/// Round-trip with non-empty intermediate (Some + Tombstone) and snapshot,
/// covering MptValue serialization through the full checkpoint path.
#[test]
fn checkpoint_roundtrips_with_nonempty_intermediate() {
    let mut mmpt = PersistedState::default();
    mmpt.height = 6000;
    mmpt.snapshot
        .insert(vec![0xaa; 20], Box::from([1u8, 2, 3]));
    mmpt.intermediate
        .insert(vec![0xbb; 24], MptValue::Some(Box::from([4u8, 5])));
    mmpt.intermediate
        .insert(vec![0xcc; 24], MptValue::Tombstone);
    mmpt.delta
        .insert(vec![0xdd; 24], MptValue::Some(Box::from([6u8])));

    let commitments = BTreeMap::new();
    let executed = BTreeMap::new();
    let prev_root = StateRootWithAuxInfo::genesis(&h(1));
    let ckpt = Checkpoint::build(
        mmpt, h(2), &prev_root, None, None, &commitments, &executed,
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ckpt.bin");
    ckpt.save(&path).unwrap();
    let loaded = Checkpoint::load(&path).unwrap().unwrap();
    let (mmpt2, ..) = loaded.into_parts().unwrap();

    assert_eq!(mmpt2.height, 6000);
    assert_eq!(mmpt2.snapshot.len(), 1);
    assert_eq!(mmpt2.snapshot[&vec![0xaa; 20]].as_ref(), &[1, 2, 3]);
    assert_eq!(mmpt2.intermediate.len(), 2);
    assert_eq!(
        mmpt2.intermediate[&vec![0xbb; 24]],
        MptValue::Some(Box::from([4u8, 5]))
    );
    assert_eq!(
        mmpt2.intermediate[&vec![0xcc; 24]],
        MptValue::Tombstone
    );
    assert_eq!(mmpt2.delta.len(), 1);
    assert_eq!(
        mmpt2.delta[&vec![0xdd; 24]],
        MptValue::Some(Box::from([6u8]))
    );
}

#[test]
fn load_absent_checkpoint_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nope.bin");
    assert!(Checkpoint::load(&path).unwrap().is_none());
}
