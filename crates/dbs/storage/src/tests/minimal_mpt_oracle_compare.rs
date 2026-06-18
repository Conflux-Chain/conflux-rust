#[test]
fn minimal_mpt_oracle_compare_get_set_delete_commit() {
    let expected_path = std::env::var("CFX_MINIMAL_MPT_EXPECTED").expect(
        "CFX_MINIMAL_MPT_EXPECTED must point to trace_standalone output",
    );
    let expected = std::fs::read_to_string(expected_path).unwrap();
    let mut expected_lines = expected.lines();

    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();

    for step in 0..800u32 {
        let id = trace_id(step);
        let key_bytes = vec![id; 20];
        let key = if id % 3 == 0 {
            StorageKey::AccountKey(&key_bytes).with_evm_space()
        } else {
            StorageKey::AccountKey(&key_bytes).with_native_space()
        };
        match step % 11 {
            0 => {
                state.delete(key).unwrap();
                assert_eq!(
                    expected_lines.next().unwrap(),
                    format!("D {step} {id}")
                );
            }
            1 | 2 | 3 | 4 | 5 | 6 | 7 => {
                let value = value_for(step, id);
                state.set(key, value.clone().into_boxed_slice()).unwrap();
                assert_eq!(
                    expected_lines.next().unwrap(),
                    format!("S {step} {id} {}", hex(&value))
                );
            }
            8 | 9 => {
                let value = state.get(key).unwrap();
                let actual =
                    value.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string());
                assert_eq!(
                    expected_lines.next().unwrap(),
                    format!("G {step} {id} {actual}")
                );
            }
            _ => {
                let root = state.compute_state_root().unwrap();
                if step == 10 && std::env::var("CFX_TRACE_DUMP_KEYS").is_ok() {
                    dump_step_10_raw_keys();
                }
                let expected = expected_lines.next().unwrap().to_string();
                let actual = format!(
                    "C {step} {} {}",
                    hex(root.state_root.delta_root.as_bytes()),
                    hex(root.aux_info.state_root_hash.as_bytes())
                );
                if expected != actual {
                    let _ = state.commit(epoch_for(step)).unwrap();
                    panic!("commit mismatch at step {step}: expected {expected}, actual {actual}");
                }
            }
        }
    }

    let root = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "F {} {}",
            hex(root.state_root.delta_root.as_bytes()),
            hex(root.aux_info.state_root_hash.as_bytes())
        )
    );
    state.commit(final_epoch()).unwrap();

    trace_storage_prefix_delta_bug(&mut expected_lines);
    trace_storage_prefix_snapshot_hit(&mut expected_lines);
    trace_set_order(&mut expected_lines);
    trace_short_account_prefix_delete_all(&mut expected_lines);
    trace_set_delete(&mut expected_lines);
    trace_snapshot_rollover(&mut expected_lines);
    trace_intermediate_prefix_bug(&mut expected_lines);
    trace_intermediate_account_prefix(&mut expected_lines);
    trace_address_prefix_filter(&mut expected_lines);
    trace_intermediate_address_prefix_filter(&mut expected_lines);
}

fn trace_storage_prefix_delta_bug<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let state_manager = new_state_manager_for_unit_test();
    let prefix = vec![0xab, 0xcd];
    let full_storage_key = [prefix.as_slice(), &[0x11; 30]].concat();
    let address = cfx_types::Address::from_slice(&[7u8; 20]);
    let key = StorageKey::new_storage_key(&address, &full_storage_key)
        .with_native_space();
    let prefix_key =
        StorageKey::new_storage_key(&address, &prefix).with_native_space();
    let value = vec![0x42, 0x24];

    let mut parent = state_manager.get_state_for_genesis_write();
    parent.set(key, value.clone().into_boxed_slice()).unwrap();
    let mut parent_epoch = cfx_types::H256::default();
    parent_epoch.as_bytes_mut()[0] = 0xa1;
    parent.compute_state_root().unwrap();
    parent.commit(parent_epoch).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch(
            StateIndex::new_for_test_only_delta_mpt(&parent_epoch),
            false,
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        expected_lines.next().unwrap(),
        format!("PSET {}", hex(&value))
    );

    let read = state.read_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("PGET {}", format_prefix_result(read))
    );

    let deleted = state.delete_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("PDEL {}", format_prefix_result(deleted))
    );

    let after = state.get(key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "PPOST {}",
            after.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );

    let mut epoch = cfx_types::H256::default();
    epoch.as_bytes_mut()[0] = 0xa2;
    state.compute_state_root().unwrap();
    state.commit(epoch).unwrap();
}

fn trace_storage_prefix_snapshot_hit<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let snapshot_epoch_count = 1;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );
    let prefix = vec![0xab, 0xcd];
    let full_storage_key = [prefix.as_slice(), &[0x22; 30]].concat();
    let address = cfx_types::Address::from_slice(&[8u8; 20]);
    let key = StorageKey::new_storage_key(&address, &full_storage_key)
        .with_native_space();
    let prefix_key =
        StorageKey::new_storage_key(&address, &prefix).with_native_space();
    let value = vec![0x55, 0x66];

    let mut state_0 = state_manager.get_state_for_genesis_write();
    state_0.set(key, value.into_boxed_slice()).unwrap();
    let mut epoch_0 = cfx_types::H256::default();
    epoch_0.as_bytes_mut()[0] = 0xb0;
    let root_0 = state_0.compute_state_root().unwrap();
    state_0.commit(epoch_0).unwrap();

    let mut state_1 = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_0,
                &root_0,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let mut epoch_1 = cfx_types::H256::default();
    epoch_1.as_bytes_mut()[0] = 0xb1;
    let root_1 = state_1.compute_state_root().unwrap();
    state_1.commit(epoch_1).unwrap();

    let mut state_2 = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_1,
                &root_1,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let mut epoch_2 = cfx_types::H256::default();
    epoch_2.as_bytes_mut()[0] = 0xb2;
    let root_2 = state_2.compute_state_root().unwrap();
    state_2.commit(epoch_2).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_2,
                &root_2,
                3,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();

    let read = state.read_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("SNPGET {}", format_prefix_result(read))
    );

    let deleted = state.delete_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("SNPDEL {}", format_prefix_result(deleted))
    );

    let after = state.get(key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "SNPPOST {}",
            after.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );

    let mut epoch = cfx_types::H256::default();
    epoch.as_bytes_mut()[0] = 0xb2;
    state.compute_state_root().unwrap();
    state.commit(epoch).unwrap();
}

fn trace_set_order<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let state_manager_a = new_state_manager_for_unit_test();
    let state_manager_b = new_state_manager_for_unit_test();
    let mut forward = state_manager_a.get_state_for_genesis_write();
    let mut reverse = state_manager_b.get_state_for_genesis_write();
    let keys: Vec<Vec<u8>> = (0u8..24).map(|id| vec![id; 20]).collect();

    for (idx, key) in keys.iter().enumerate() {
        forward
            .set(
                account_key_for_bytes(key),
                vec![idx as u8, idx.wrapping_mul(3) as u8].into_boxed_slice(),
            )
            .unwrap();
    }
    for (idx, key) in keys.iter().enumerate().rev() {
        reverse
            .set(
                account_key_for_bytes(key),
                vec![idx as u8, idx.wrapping_mul(3) as u8].into_boxed_slice(),
            )
            .unwrap();
    }

    let a = forward.compute_state_root().unwrap();
    let b = reverse.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ORDER {} {} {}",
            hex(a.state_root.delta_root.as_bytes()),
            hex(b.state_root.delta_root.as_bytes()),
            a.state_root.delta_root == b.state_root.delta_root
        )
    );

    let mut epoch_a = cfx_types::H256::default();
    epoch_a.as_bytes_mut()[0] = 0xc1;
    forward.commit(epoch_a).unwrap();
    let mut epoch_b = cfx_types::H256::default();
    epoch_b.as_bytes_mut()[0] = 0xc2;
    reverse.commit(epoch_b).unwrap();
}

fn trace_short_account_prefix_delete_all<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();
    for id in 0u8..8 {
        state
            .set(
                StorageKey::AccountKey(&[0x31, id]).with_native_space(),
                vec![id, id + 1].into_boxed_slice(),
            )
            .unwrap();
    }
    for id in 0u8..5 {
        state
            .set(
                StorageKey::AccountKey(&[0x42, id]).with_native_space(),
                vec![id + 10].into_boxed_slice(),
            )
            .unwrap();
    }

    let deleted = state
        .delete_all(StorageKey::AccountKey(&[0x31]).with_native_space())
        .unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("APDEL {}", format_prefix_result(deleted))
    );

    let deleted_again = state
        .delete_all(StorageKey::AccountKey(&[0x31]).with_native_space())
        .unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("APDEL2 {}", format_prefix_result(deleted_again))
    );

    let kept = state
        .get(StorageKey::AccountKey(&[0x42, 3]).with_native_space())
        .unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "APKEEP {}",
            kept.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );

    let mut epoch = cfx_types::H256::default();
    epoch.as_bytes_mut()[0] = 0xc3;
    state.compute_state_root().unwrap();
    state.commit(epoch).unwrap();
}

fn trace_set_delete<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();
    let key_bytes = vec![0x5a; 20];
    let key = account_key_for_bytes(&key_bytes);
    state.set(key, Box::from([0x99u8])).unwrap();
    let before = state.get(key).unwrap();
    state.delete(key).unwrap();
    let after = state.get(key).unwrap();
    let root = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "SETDEL {} {} {}",
            before.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            after.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            hex(root.state_root.delta_root.as_bytes())
        )
    );

    let mut epoch = cfx_types::H256::default();
    epoch.as_bytes_mut()[0] = 0xc4;
    state.commit(epoch).unwrap();
}

fn trace_snapshot_rollover<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let snapshot_epoch_count = 2;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );
    let key_a_bytes = vec![0x21; 20];
    let key_b_bytes = vec![0x22; 20];
    let key_c_bytes = vec![0x23; 20];
    let key_d_bytes = vec![0x20; 20];
    let key_a = account_key_for_bytes(&key_a_bytes);
    let key_b = account_key_for_bytes(&key_b_bytes);
    let key_c = account_key_for_bytes(&key_c_bytes);
    let key_d = account_key_for_bytes(&key_d_bytes);

    let mut state = state_manager.get_state_for_genesis_write();
    state.set(key_a, Box::from([0xa1u8])).unwrap();
    let root_1 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL1 {}", format_root(&root_1))
    );
    let epoch_1 = rollover_epoch(1);
    state.commit(epoch_1).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_1,
                &root_1,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_2 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL2 {}", format_root(&root_2))
    );
    let epoch_2 = rollover_epoch(2);
    state.commit(epoch_2).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_2,
                &root_2,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_3 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL3 {}", format_root(&root_3))
    );
    let value_a = state.get(key_a).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ROLL3GET {}",
            value_a.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    let epoch_3 = rollover_epoch(3);
    state.commit(epoch_3).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_3,
                &root_3,
                3,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    state.set(key_b, Box::from([0xb2u8])).unwrap();
    let root_4 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL4 {}", format_root(&root_4))
    );
    let epoch_4 = rollover_epoch(4);
    state.commit(epoch_4).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_4,
                &root_4,
                4,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_5 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL5 {}", format_root(&root_5))
    );
    let value_a = state.get(key_a).unwrap();
    let value_b = state.get(key_b).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ROLL5GET {} {}",
            value_a.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_b.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    let epoch_5 = rollover_epoch(5);
    state.commit(epoch_5).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_5,
                &root_5,
                5,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    state.delete(key_a).unwrap();
    state.set(key_c, Box::from([0xc3u8])).unwrap();
    state.set(key_d, Box::from([0xd4u8])).unwrap();
    let root_6 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL6 {}", format_root(&root_6))
    );
    let epoch_6 = rollover_epoch(6);
    state.commit(epoch_6).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_6,
                &root_6,
                6,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_7 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL7 {}", format_root(&root_7))
    );
    let value_a = state.get(key_a).unwrap();
    let value_b = state.get(key_b).unwrap();
    let value_c = state.get(key_c).unwrap();
    let value_d = state.get(key_d).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ROLL7GET {} {} {} {}",
            value_a.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_b.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_c.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_d.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    let epoch_7 = rollover_epoch(7);
    state.commit(epoch_7).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_7,
                &root_7,
                7,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_8 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL8 {}", format_root(&root_8))
    );
    let epoch_8 = rollover_epoch(8);
    state.commit(epoch_8).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_8,
                &root_8,
                8,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_9 = state.compute_state_root().unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ROLL9 {}", format_root(&root_9))
    );
    let value_a = state.get(key_a).unwrap();
    let value_b = state.get(key_b).unwrap();
    let value_c = state.get(key_c).unwrap();
    let value_d = state.get(key_d).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ROLL9GET {} {} {} {}",
            value_a.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_b.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_c.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            value_d.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    state.commit(rollover_epoch(9)).unwrap();
}

fn trace_intermediate_prefix_bug<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let snapshot_epoch_count = 2;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );
    let prefix = vec![0xab, 0xcd];
    let full_storage_key = [prefix.as_slice(), &[0x33; 30]].concat();
    let address = cfx_types::Address::from_slice(&[9u8; 20]);
    let key = StorageKey::new_storage_key(&address, &full_storage_key)
        .with_native_space();
    let prefix_key =
        StorageKey::new_storage_key(&address, &prefix).with_native_space();

    let mut state = state_manager.get_state_for_genesis_write();
    state.set(key, Box::from([0x77u8])).unwrap();
    let root_1 = state.compute_state_root().unwrap();
    let epoch_1 = prefix_epoch(1);
    state.commit(epoch_1).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_1,
                &root_1,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_2 = state.compute_state_root().unwrap();
    let epoch_2 = prefix_epoch(2);
    state.commit(epoch_2).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_2,
                &root_2,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();

    let read = state.read_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("IPGET {}", format_prefix_result(read))
    );
    let deleted = state.delete_all(prefix_key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("IPDEL {}", format_prefix_result(deleted))
    );
    let after = state.get(key).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "IPPOST {}",
            after.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    state.commit(prefix_epoch(3)).unwrap();
}

fn trace_intermediate_account_prefix<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let snapshot_epoch_count = 2;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );
    let mut state = state_manager.get_state_for_genesis_write();
    for id in 0u8..4 {
        state
            .set(
                StorageKey::AccountKey(&[0x61, id]).with_native_space(),
                vec![id + 1].into_boxed_slice(),
            )
            .unwrap();
    }
    state
        .set(
            StorageKey::AccountKey(&[0x62, 0]).with_native_space(),
            Box::from([0x99u8]),
        )
        .unwrap();
    let root_1 = state.compute_state_root().unwrap();
    let epoch_1 = prefix_epoch(5);
    state.commit(epoch_1).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_1,
                &root_1,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_2 = state.compute_state_root().unwrap();
    let epoch_2 = prefix_epoch(6);
    state.commit(epoch_2).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_2,
                &root_2,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let prefix = StorageKey::AccountKey(&[0x61]).with_native_space();
    let read = state.read_all(prefix).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("IAPGET {}", format_prefix_result(read))
    );
    let deleted = state.delete_all(prefix).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("IAPDEL {}", format_prefix_result(deleted))
    );
    let removed = state
        .get(StorageKey::AccountKey(&[0x61, 2]).with_native_space())
        .unwrap();
    let kept = state
        .get(StorageKey::AccountKey(&[0x62, 0]).with_native_space())
        .unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "IAPPOST {} {}",
            removed.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string()),
            kept.map(|v| hex(&v)).unwrap_or_else(|| "-".to_string())
        )
    );
    state.compute_state_root().unwrap();
    state.commit(prefix_epoch(7)).unwrap();
}

fn trace_address_prefix_filter<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let state_manager = new_state_manager_for_unit_test();
    let mut state = state_manager.get_state_for_genesis_write();
    let keep = StorageKey::AccountKey(&[0x52, 0x01]).with_native_space();
    let delete = StorageKey::AccountKey(&[0x51, 0x01]).with_native_space();
    let prefix = StorageKey::AddressPrefixKey(&[0x51]).with_native_space();

    state.set(keep, Box::from([0x10u8])).unwrap();
    state.set(delete, Box::from([0x20u8])).unwrap();
    let deleted = state.delete_all(prefix).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("ADDRDEL {}", format_prefix_result(deleted))
    );
    let keep_value = state.get(keep).unwrap();
    let delete_value = state.get(delete).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "ADDRPOST {} {}",
            keep_value
                .map(|v| hex(&v))
                .unwrap_or_else(|| "-".to_string()),
            delete_value
                .map(|v| hex(&v))
                .unwrap_or_else(|| "-".to_string())
        )
    );
    state.commit(prefix_epoch(4)).unwrap();
}

fn trace_intermediate_address_prefix_filter<'a, I>(expected_lines: &mut I)
where
    I: Iterator<Item = &'a str>,
{
    let snapshot_epoch_count = 2;
    let state_manager =
        new_state_manager_for_unit_test_with_snapshot_epoch_count(
            snapshot_epoch_count,
        );
    let mut state = state_manager.get_state_for_genesis_write();
    let keep = StorageKey::AccountKey(&[0x52, 0x02]).with_native_space();
    let delete = StorageKey::AccountKey(&[0x51, 0x02]).with_native_space();
    let prefix = StorageKey::AddressPrefixKey(&[0x51]).with_native_space();

    state.set(keep, Box::from([0x30u8])).unwrap();
    state.set(delete, Box::from([0x40u8])).unwrap();
    let root_1 = state.compute_state_root().unwrap();
    let epoch_1 = prefix_epoch(8);
    state.commit(epoch_1).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_1,
                &root_1,
                1,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let root_2 = state.compute_state_root().unwrap();
    let epoch_2 = prefix_epoch(9);
    state.commit(epoch_2).unwrap();

    let mut state = state_manager
        .get_state_for_next_epoch_inner(
            StateIndex::new_for_next_epoch(
                &epoch_2,
                &root_2,
                2,
                snapshot_epoch_count,
            ),
            true,
            false,
        )
        .unwrap()
        .unwrap();
    let deleted = state.delete_all(prefix).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!("IADDRDEL {}", format_prefix_result(deleted))
    );
    let keep_value = state.get(keep).unwrap();
    let delete_value = state.get(delete).unwrap();
    assert_eq!(
        expected_lines.next().unwrap(),
        format!(
            "IADDRPOST {} {}",
            keep_value
                .map(|v| hex(&v))
                .unwrap_or_else(|| "-".to_string()),
            delete_value
                .map(|v| hex(&v))
                .unwrap_or_else(|| "-".to_string())
        )
    );
    state.compute_state_root().unwrap();
    state.commit(prefix_epoch(10)).unwrap();
}

fn epoch_for(step: u32) -> cfx_types::H256 {
    let mut h = cfx_types::H256::default();
    h.as_bytes_mut()[0] = step as u8;
    h.as_bytes_mut()[1] = (step >> 8) as u8;
    h
}

fn prefix_epoch(step: u8) -> cfx_types::H256 {
    let mut h = cfx_types::H256::default();
    h.as_bytes_mut()[0] = 0xe0;
    h.as_bytes_mut()[1] = step;
    h
}

fn rollover_epoch(step: u8) -> cfx_types::H256 {
    let mut h = cfx_types::H256::default();
    h.as_bytes_mut()[0] = 0xd0;
    h.as_bytes_mut()[1] = step;
    h
}

fn trace_id(step: u32) -> u8 {
    ((step.wrapping_mul(37).wrapping_add(11)) % 64) as u8
}

fn account_key_for_bytes(
    key_bytes: &[u8],
) -> primitives::StorageKeyWithSpace<'_> {
    if key_bytes.len() == 20 && key_bytes[0] % 3 == 0 {
        StorageKey::AccountKey(key_bytes).with_evm_space()
    } else {
        StorageKey::AccountKey(key_bytes).with_native_space()
    }
}

fn value_for(step: u32, id: u8) -> Vec<u8> {
    let len = 1 + (step as usize % 47);
    (0..len)
        .map(|i| id.wrapping_add(step as u8).wrapping_add(i as u8))
        .collect()
}

fn dump_step_10_raw_keys() {
    let padding = primitives::GENESIS_DELTA_MPT_KEY_PADDING.clone();
    for step in 1..=7u32 {
        let id = trace_id(step);
        let key_bytes = vec![id; 20];
        let key = if id % 3 == 0 {
            StorageKey::AccountKey(&key_bytes).with_evm_space()
        } else {
            StorageKey::AccountKey(&key_bytes).with_native_space()
        };
        eprintln!(
            "RAW {step} {id} {}",
            hex(&key.to_delta_mpt_key_bytes(&padding))
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn format_prefix_result(values: Option<Vec<(Vec<u8>, Box<[u8]>)>>) -> String {
    let Some(mut values) = values else {
        return "-".to_string();
    };
    values.sort();
    values
        .into_iter()
        .map(|(key, value)| format!("{}={}", hex(&key), hex(&value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_root(root: &cfx_internal_common::StateRootWithAuxInfo) -> String {
    format!(
        "{}:{}:{}:{}",
        hex(root.state_root.snapshot_root.as_bytes()),
        hex(root.state_root.intermediate_delta_root.as_bytes()),
        hex(root.state_root.delta_root.as_bytes()),
        hex(root.aux_info.state_root_hash.as_bytes())
    )
}

fn final_epoch() -> cfx_types::H256 {
    let mut h = cfx_types::H256::default();
    h.as_bytes_mut()[0] = 0xfe;
    h
}

use crate::{
    state::StateTrait,
    state_manager::*,
    tests::{
        new_state_manager_for_unit_test,
        new_state_manager_for_unit_test_with_snapshot_epoch_count,
    },
};
use primitives::StorageKey;
