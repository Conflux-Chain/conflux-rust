// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This file defines transaction store APIs that are related to committed
//! signed transactions.

use crate::{
    change_set::ChangeSet,
    errors::DiemDbError,
    schema::{
        transaction::TransactionSchema,
        transaction_by_account::TransactionByAccountSchema,
    },
};
use anyhow::Result;
use diem_types::{
    block_metadata::BlockMetadata,
    transaction::{Transaction, Version},
};
use schemadb::DB;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct TransactionStore {
    db: Arc<DB>,
}

impl TransactionStore {
    pub fn new(db: Arc<DB>) -> Self { Self { db } }

    /// Get signed transaction given `version`
    pub fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db.get::<TransactionSchema>(&version)?.ok_or_else(|| {
            DiemDbError::NotFound(format!("Txn {}", version)).into()
        })
    }

    /// Returns the block metadata carried on the block metadata transaction at
    /// or preceding `version`, together with the version of the block
    /// metadata transaction. Returns None if there's no such transaction at
    /// or preceding `version` (it's likely the genesis version 0).
    pub fn get_block_metadata(
        &self, version: Version,
    ) -> Result<Option<(Version, BlockMetadata)>> {
        // Maximum TPS from benchmark is around 1000.
        const MAX_VERSIONS_TO_SEARCH: usize = 1000 * 3;

        // Linear search via `DB::rev_iter()` here, NOT expecting performance
        // hit, due to the fact that the iterator caches data block and
        // that there are limited number of transactions in each block.
        let mut iter =
            self.db.rev_iter::<TransactionSchema>(Default::default())?;
        iter.seek(&version)?;
        for res in iter.take(MAX_VERSIONS_TO_SEARCH) {
            let (v, txn) = res?;
            if let Transaction::BlockMetadata(block_meta) = txn {
                return Ok(Some((v, block_meta)));
            } else if v == 0 {
                return Ok(None);
            }
        }

        Err(DiemDbError::NotFound(format!(
            "BlockMetadata preceding version {}",
            version
        ))
        .into())
    }

    /// Save signed transaction at `version`
    pub fn put_transaction(
        &self, version: Version, transaction: &Transaction, cs: &mut ChangeSet,
    ) -> Result<()> {
        if let Transaction::UserTransaction(txn) = transaction {
            // TODO(lpl): Find a proper way to keep account-related info.
            cs.batch.put::<TransactionByAccountSchema>(
                &(txn.sender(), 0),
                &version,
            )?;
        }
        cs.batch.put::<TransactionSchema>(&version, &transaction)?;

        Ok(())
    }
}

#[cfg(test)]
mod test;
