// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use diem_config::{config::NodeConfig, utils};
use diem_types::account_address::HashAccountAddress;
#[cfg(test)]
use pos_ledger_db::test_helper::arb_blocks_to_commit;
use itertools::zip_eq;
use proptest::prelude::*;
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use storage_client::StorageClient;

fn start_test_storage_with_client(
) -> (JoinHandle<()>, diem_temppath::TempPath, StorageClient) {
    let mut config = NodeConfig::random();
    let tmp_dir = diem_temppath::TempPath::new();

    let server_port = utils::get_available_port();
    config.storage.address =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    // Test timeout of 5 seconds
    config.storage.timeout_ms = 5_000;

    let db = Arc::new(DiemDB::new_for_test(&tmp_dir));
    let storage_server_handle = start_storage_service_with_db(&config, db);

    let client =
        StorageClient::new(&config.storage.address, config.storage.timeout_ms);
    (storage_server_handle, tmp_dir, client)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]
    #[test]
    fn test_simple_storage_service(blocks in arb_blocks_to_commit().no_shrink()) {
        let (_handle, _tmp_dir, client) =
            start_test_storage_with_client();

        let mut version = 0;
        let mut all_accounts = BTreeMap::new();
        let mut all_txns = vec![];

        for (txns_to_commit, ledger_info_with_sigs) in &blocks {
            client.save_transactions(
                txns_to_commit.clone(),
                version, /* first_version */
                Some(ledger_info_with_sigs.clone()),
            ).unwrap();
            version += txns_to_commit.len() as u64;
            let mut account_states = HashMap::new();
            // Get the ground truth of account states.
            txns_to_commit.iter().for_each(|txn_to_commit| {
                account_states.extend(txn_to_commit.account_states().clone())
            });

            // Record all account states.
            for (address, blob) in account_states.iter() {
                all_accounts.insert(address.hash(), blob.clone());
            }

            // Record all transactions.
            all_txns.extend(
                txns_to_commit
                    .iter()
                    .map(|txn_to_commit| txn_to_commit.transaction().clone()),
            );

            let account_states_returned = account_states
                .keys()
                .map(|address| client.get_account_state_with_proof_by_version(*address, version - 1).unwrap())
                .collect::<Vec<_>>();
            let startup_info = client.get_startup_info().unwrap().unwrap();
            for ((address, blob), state_with_proof) in zip_eq(account_states, account_states_returned) {
                 prop_assert_eq!(&Some(blob), &state_with_proof.0);
                 prop_assert!(state_with_proof.1
                     .verify(
                         startup_info.committed_tree_state.account_state_root_hash,
                         address.hash(),
                         state_with_proof.0.as_ref()
                     )
                     .is_ok());
            }
        }
    }
}
