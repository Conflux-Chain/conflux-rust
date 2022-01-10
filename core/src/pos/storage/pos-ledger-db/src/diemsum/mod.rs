// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Order, PosLedgerDB, MAX_LIMIT};
use anyhow::{ensure, format_err, Result};
use diem_config::config::RocksdbConfig;
use diem_types::{
    account_address::AccountAddress,
    account_state_blob::AccountStateBlob,
    contract_event::ContractEvent,
    event::EventKey,
    transaction::{Transaction, Version},
};
use std::{convert::AsRef, path::Path};
use storage_interface::{DbReader, StartupInfo};

pub struct Diemsum {
    db: PosLedgerDB,
}

impl Diemsum {
    pub fn new<P: AsRef<Path> + Clone>(db_root_path: P) -> Result<Self> {
        let db = PosLedgerDB::open(
            db_root_path,
            true, /* read only */
            None, /* no prune_window */
            RocksdbConfig::default(),
        )?;
        Ok(Diemsum { db })
    }

    pub fn get_startup_info(&self) -> Result<StartupInfo> {
        self.db
            .ledger_store
            .get_startup_info(false)?
            .ok_or_else(|| format_err!("DB is empty"))
    }

    pub fn get_committed_version(&self) -> Result<Version> {
        Ok(self
            .db
            .get_startup_info(false)?
            .ok_or_else(|| format_err!("No committed ledger info found."))?
            .latest_ledger_info
            .ledger_info()
            .version())
    }

    pub fn scan_txn_by_version(
        &self, from_version: Version, to_version: Version,
    ) -> Result<Vec<Transaction>> {
        ensure!(
            to_version >= from_version,
            "'from' version {} > 'to' version {}",
            from_version,
            to_version
        );
        let num_txns = to_version - from_version;
        let txn_iter = self
            .db
            .transaction_store
            .get_transaction_iter(from_version, num_txns as usize)?;
        txn_iter.collect::<Result<Vec<_>>>()
    }

    pub fn get_txn_by_version(&self, version: Version) -> Result<Transaction> {
        self.db.transaction_store.get_transaction(version)
    }

    pub fn get_account_state_by_version(
        &self, address: AccountAddress, version: Version,
    ) -> Result<Option<AccountStateBlob>> {
        self.db
            .state_store
            .get_account_state_with_proof_by_version(address, version)
            .map(|blob_and_proof| blob_and_proof.0)
    }

    pub fn get_events_by_version(
        &self, version: Version,
    ) -> Result<Vec<ContractEvent>> {
        self.db.event_store.get_events_by_version(version)
    }
}
