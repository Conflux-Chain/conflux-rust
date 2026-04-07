// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::PosLedgerDB;
use diem_temppath::TempPath;
use proptest::{collection::vec, prelude::*};

fn verify(
    store: &LedgerStore, txn_infos: &[TransactionInfo], first_version: Version,
) {
    txn_infos
        .iter()
        .enumerate()
        .for_each(|(idx, expected_txn_info)| {
            let version = first_version + idx as u64;
            let txn_info = store.get_transaction_info(version).unwrap();
            assert_eq!(&txn_info, expected_txn_info);
        })
}

fn save(
    store: &LedgerStore, first_version: Version, txn_infos: &[TransactionInfo],
) -> HashValue {
    let mut cs = ChangeSet::new();
    let root_hash = store
        .put_transaction_infos(first_version, &txn_infos, &mut cs)
        .unwrap();
    store.db.write_schemas(cs.batch, true).unwrap();
    root_hash
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn test_transaction_info_put_get_verify(
        batch1 in vec(any::<TransactionInfo>(), 1..100),
        batch2 in vec(any::<TransactionInfo>(), 1..100),
    ) {
        let tmp_dir = TempPath::new();
        let db = PosLedgerDB::new_for_test(&tmp_dir);
        let store = &db.ledger_store;

        // insert two batches of transaction infos
        let _root_hash1 = save(store, 0, &batch1);
        let _root_hash2 = save(store, batch1.len() as u64, &batch2);

        // retrieve all transaction infos and verify
        verify(store, &batch1, 0);
        verify(store, &batch2, batch1.len() as u64);
    }
}
