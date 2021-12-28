// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This file defines ledger store APIs that are related to the main ledger
//! accumulator, from the root(LedgerInfo) to leaf(TransactionInfo).

use std::{ops::Deref, sync::Arc};

use anyhow::{ensure, format_err, Result};
use arc_swap::ArcSwap;
use itertools::Itertools;

use accumulator::{HashReader, MerkleAccumulator};
use diem_crypto::{
    hash::{CryptoHash, TransactionAccumulatorHasher},
    HashValue,
};
use diem_logger::prelude::*;
use diem_types::{
    committed_block::CommittedBlock,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    proof::{
        definition::LeafCount, position::Position, AccumulatorConsistencyProof,
        TransactionAccumulatorProof, TransactionAccumulatorRangeProof,
        TransactionInfoWithProof,
    },
    reward_distribution_event::RewardDistributionEvent,
    term_state::PosState,
    transaction::{TransactionInfo, Version},
};
use schemadb::{ReadOptions, SchemaIterator, DB};
use storage_interface::{StartupInfo, TreeState};

use crate::{
    change_set::ChangeSet,
    errors::DiemDbError,
    schema::{
        committed_block::CommittedBlockSchema,
        committed_block_by_view::CommittedBlockByViewSchema,
        epoch_by_version::EpochByVersionSchema, ledger_info::LedgerInfoSchema,
        ledger_info_by_block::LedgerInfoByBlockSchema,
        ledger_info_by_voted_block::LedgerInfoByVotedBlockSchema,
        pos_state::PosStateSchema, reward_event::RewardEventSchema,
        transaction_accumulator::TransactionAccumulatorSchema,
        transaction_info::TransactionInfoSchema,
    },
};

#[derive(Debug)]
pub(crate) struct LedgerStore {
    db: Arc<DB>,

    /// We almost always need the latest ledger info and signatures to serve
    /// read requests, so we cache it in memory in order to avoid reading
    /// DB and deserializing the object frequently. It should be updated
    /// every time new ledger info and signatures are persisted.
    latest_ledger_info: ArcSwap<Option<LedgerInfoWithSignatures>>,

    /// latest pos state based on `current_view`. It's not always in sync with
    /// `latest_ledger_info`.
    latest_pos_state: ArcSwap<PosState>,
}

impl LedgerStore {
    pub fn new(db: Arc<DB>) -> Self {
        // Upon restart, read the latest ledger info and signatures and cache
        // them in memory.
        let ledger_info = {
            let mut iter = db
                .iter::<LedgerInfoSchema>(ReadOptions::default())
                .expect("Constructing iterator should work.");
            iter.seek_to_last();
            iter.next()
                .transpose()
                .expect("Reading latest ledger info from DB should work.")
                .map(|kv| kv.1)
        };

        let latest_pos_state = ledger_info
            .as_ref()
            .map(|ledger_info| {
                db.get::<PosStateSchema>(
                    &ledger_info.ledger_info().consensus_block_id(),
                )
                .unwrap()
                .expect("pos state and ledger info both committed")
            })
            .unwrap_or(PosState::new_empty());
        let ledger_store = Self {
            db,
            latest_ledger_info: ArcSwap::from(Arc::new(ledger_info.clone())),
            latest_pos_state: ArcSwap::from(Arc::new(latest_pos_state)),
        };
        ledger_store
    }

    pub fn get_epoch(&self, version: Version) -> Result<u64> {
        let mut iter = self
            .db
            .iter::<EpochByVersionSchema>(ReadOptions::default())?;
        // Search for the end of the previous epoch.
        iter.seek_for_prev(&version)?;
        let (epoch_end_version, epoch) = match iter.next().transpose()? {
            Some(x) => x,
            None => {
                // There should be a genesis LedgerInfo at version 0 (genesis
                // only consists of one transaction), so this
                // normally doesn't happen. However this part of
                // implementation doesn't need to rely on this assumption.
                return Ok(0);
            }
        };
        ensure!(
            epoch_end_version <= version,
            "DB corruption: looking for epoch for version {}, got epoch {} ends at version {}",
            version,
            epoch,
            epoch_end_version
        );
        // If the obtained epoch ended before the given version, return epoch+1,
        // otherwise the given version is exactly the last version of
        // the found epoch.
        Ok(if epoch_end_version < version {
            epoch + 1
        } else {
            epoch
        })
    }

    /// Gets ledger info at specified version and ensures it's an epoch ending.
    pub fn get_epoch_ending_ledger_info(
        &self, version: Version,
    ) -> Result<LedgerInfoWithSignatures> {
        let epoch = self.get_epoch(version)?;
        let li = self.db.get::<LedgerInfoSchema>(&epoch)?.ok_or_else(|| {
            DiemDbError::NotFound(format!("LedgerInfo for epoch {}.", epoch))
        })?;
        ensure!(
            li.ledger_info().version() == version,
            "Epoch {} didn't end at version {}",
            epoch,
            version,
        );
        li.ledger_info().next_epoch_state().ok_or_else(|| {
            format_err!("Not an epoch change at version {}", version)
        })?;

        Ok(li)
    }

    pub fn get_latest_ledger_info_option(
        &self,
    ) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }

    pub fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option().ok_or_else(|| {
            DiemDbError::NotFound(String::from("Genesis LedgerInfo")).into()
        })
    }

    pub fn set_latest_ledger_info(
        &self, ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) {
        self.latest_ledger_info
            .store(Arc::new(Some(ledger_info_with_sigs)));
    }

    pub fn get_latest_ledger_info_in_epoch(
        &self, epoch: u64,
    ) -> Result<LedgerInfoWithSignatures> {
        self.db.get::<LedgerInfoSchema>(&epoch)?.ok_or_else(|| {
            DiemDbError::NotFound(format!("Last LedgerInfo of epoch {}", epoch))
                .into()
        })
    }

    fn get_epoch_state(&self, epoch: u64) -> Result<EpochState> {
        ensure!(epoch > 0, "EpochState only queryable for epoch >= 1.",);

        let ledger_info_with_sigs = self
            .db
            .get::<LedgerInfoSchema>(&(epoch - 1))?
            .ok_or_else(|| {
                DiemDbError::NotFound(format!(
                    "Last LedgerInfo of epoch {}",
                    epoch - 1
                ))
            })?;
        let latest_epoch_state = ledger_info_with_sigs
            .ledger_info()
            .next_epoch_state()
            .ok_or_else(|| {
                format_err!(
                    "Last LedgerInfo in epoch must carry next_epoch_state."
                )
            })?;

        Ok(latest_epoch_state.clone())
    }

    pub fn get_pos_state(&self, block_hash: &HashValue) -> Result<PosState> {
        self.db.get::<PosStateSchema>(block_hash)?.ok_or_else(|| {
            format_err!("PoS State is not found for block {}", block_hash)
        })
    }

    pub fn get_tree_state(
        &self, num_transactions: LeafCount, transaction_info: TransactionInfo,
    ) -> Result<TreeState> {
        Ok(TreeState::new(
            num_transactions,
            self.get_frozen_subtree_hashes(num_transactions)?,
            transaction_info.state_root_hash(),
        ))
    }

    pub fn get_frozen_subtree_hashes(
        &self, num_transactions: LeafCount,
    ) -> Result<Vec<HashValue>> {
        Accumulator::get_frozen_subtree_hashes(self, num_transactions)
    }

    pub fn get_startup_info(
        &self, need_pos_state: bool,
    ) -> Result<Option<StartupInfo>> {
        // Get the latest ledger info. Return None if not bootstrapped.
        let latest_ledger_info = match self.get_latest_ledger_info_option() {
            Some(x) => x,
            None => return Ok(None),
        };
        let latest_epoch_state_if_not_in_li =
            match latest_ledger_info.ledger_info().next_epoch_state() {
                Some(_) => None,
                // If the latest LedgerInfo doesn't carry a validator set, we
                // look for the previous LedgerInfo which should
                // always carry a validator set.
                None => Some(self.get_epoch_state(
                    latest_ledger_info.ledger_info().epoch(),
                )?),
            };

        let li_version = latest_ledger_info.ledger_info().version();
        let (latest_version, latest_txn_info) =
            self.get_latest_transaction_info()?;
        assert!(latest_version >= li_version);
        let (commited_tree_state, synced_tree_state) = if latest_version
            == li_version
        {
            (
                self.get_tree_state(latest_version + 1, latest_txn_info)?,
                None,
            )
        } else {
            let commited_txn_info = self.get_transaction_info(li_version)?;
            (
                self.get_tree_state(li_version + 1, commited_txn_info)?,
                Some(self.get_tree_state(latest_version + 1, latest_txn_info)?),
            )
        };
        diem_trace!("get_pos_state: start");
        let pos_state = if need_pos_state {
            self.get_pos_state(
                &latest_ledger_info.ledger_info().consensus_block_id(),
            )?
        } else {
            PosState::new_empty()
        };

        diem_trace!("get_startup_info: ends");
        Ok(Some(StartupInfo::new(
            latest_ledger_info,
            latest_epoch_state_if_not_in_li,
            commited_tree_state,
            synced_tree_state,
            pos_state,
        )))
    }

    /// Get transaction info given `version`
    pub fn get_transaction_info(
        &self, version: Version,
    ) -> Result<TransactionInfo> {
        self.db
            .get::<TransactionInfoSchema>(&version)?
            .ok_or_else(|| {
                format_err!("No TransactionInfo at version {}", version)
            })
    }

    pub fn get_latest_transaction_info_option(
        &self,
    ) -> Result<Option<(Version, TransactionInfo)>> {
        let mut iter = self
            .db
            .iter::<TransactionInfoSchema>(ReadOptions::default())?;
        iter.seek_to_last();
        iter.next().transpose()
    }

    /// Get latest transaction info together with its version. Note that during
    /// node syncing, this version can be greater than what's in the latest
    /// LedgerInfo.
    pub fn get_latest_transaction_info(
        &self,
    ) -> Result<(Version, TransactionInfo)> {
        self.get_latest_transaction_info_option()?.ok_or_else(|| {
            DiemDbError::NotFound(String::from("Genesis TransactionInfo."))
                .into()
        })
    }

    /// Gets an iterator that yields `num_transaction_infos` transaction infos
    /// starting from `start_version`.
    pub fn get_transaction_info_iter(
        &self, start_version: Version, num_transaction_infos: usize,
    ) -> Result<TransactionInfoIter> {
        let mut iter = self
            .db
            .iter::<TransactionInfoSchema>(ReadOptions::default())?;
        iter.seek(&start_version)?;
        Ok(TransactionInfoIter {
            inner: iter,
            expected_next_version: start_version,
            end_version: start_version
                .checked_add(num_transaction_infos as u64)
                .ok_or_else(|| {
                    format_err!("Too many transaction infos requested.")
                })?,
        })
    }

    /// Gets an iterator that yields epoch ending ledger infos, starting
    /// from `start_epoch`, and ends at the one before `end_epoch`
    pub fn get_epoch_ending_ledger_info_iter(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Result<EpochEndingLedgerInfoIter> {
        let mut iter =
            self.db.iter::<LedgerInfoSchema>(ReadOptions::default())?;
        iter.seek(&start_epoch)?;
        Ok(EpochEndingLedgerInfoIter {
            inner: iter,
            next_epoch: start_epoch,
            end_epoch,
        })
    }

    /// Get transaction info at `version` with proof towards root of ledger at
    /// `ledger_version`.
    pub fn get_transaction_info_with_proof(
        &self, version: Version, ledger_version: Version,
    ) -> Result<TransactionInfoWithProof> {
        Ok(TransactionInfoWithProof::new(
            self.get_transaction_proof(version, ledger_version)?,
            self.get_transaction_info(version)?,
        ))
    }

    /// Get proof for transaction at `version` towards root of ledger at
    /// `ledger_version`.
    pub fn get_transaction_proof(
        &self, version: Version, ledger_version: Version,
    ) -> Result<TransactionAccumulatorProof> {
        Accumulator::get_proof(
            self,
            ledger_version + 1, /* num_leaves */
            version,
        )
    }

    /// Get proof for `num_txns` consecutive transactions starting from
    /// `start_version` towards root of ledger at `ledger_version`.
    pub fn get_transaction_range_proof(
        &self, start_version: Option<Version>, num_txns: u64,
        ledger_version: Version,
    ) -> Result<TransactionAccumulatorRangeProof>
    {
        Accumulator::get_range_proof(
            self,
            ledger_version + 1, /* num_leaves */
            start_version,
            num_txns,
        )
    }

    /// Gets proof that shows the ledger at `ledger_version` is consistent with
    /// the ledger at `client_known_version`.
    pub fn get_consistency_proof(
        &self, client_known_version: Version, ledger_version: Version,
    ) -> Result<AccumulatorConsistencyProof> {
        Accumulator::get_consistency_proof(
            self,
            ledger_version + 1,
            client_known_version + 1,
        )
    }

    /// Write `txn_infos` to `batch`. Assigned `first_version` to the the
    /// version number of the first transaction, and so on.
    pub fn put_transaction_infos(
        &self, first_version: u64, txn_infos: &[TransactionInfo],
        cs: &mut ChangeSet,
    ) -> Result<HashValue>
    {
        // write txn_info
        (first_version..first_version + txn_infos.len() as u64)
            .zip_eq(txn_infos.iter())
            .try_for_each(|(version, txn_info)| {
                cs.batch.put::<TransactionInfoSchema>(&version, txn_info)
            })?;

        // write hash of txn_info into the accumulator
        let txn_hashes: Vec<HashValue> =
            txn_infos.iter().map(TransactionInfo::hash).collect();
        let (root_hash, writes) = Accumulator::append(
            self,
            first_version, /* num_existing_leaves */
            &txn_hashes,
        )?;
        writes.iter().try_for_each(|(pos, hash)| {
            cs.batch.put::<TransactionAccumulatorSchema>(pos, hash)
        })?;
        Ok(root_hash)
    }

    /// Write `ledger_info` to `cs`.
    pub fn put_ledger_info(
        &self, ledger_info_with_sigs: &LedgerInfoWithSignatures,
        cs: &mut ChangeSet,
    ) -> Result<()>
    {
        let ledger_info = ledger_info_with_sigs.ledger_info();

        if ledger_info.ends_epoch() {
            // This is the last version of the current epoch, update the epoch
            // by version index.
            cs.batch.put::<EpochByVersionSchema>(
                &ledger_info.version(),
                &ledger_info.epoch(),
            )?;
        }
        cs.batch.put::<LedgerInfoByBlockSchema>(
            &ledger_info.consensus_block_id(),
            ledger_info_with_sigs,
        )?;
        cs.batch.put::<LedgerInfoSchema>(
            &ledger_info.epoch(),
            ledger_info_with_sigs,
        )
    }

    pub fn put_pos_state(
        &self, block_hash: &HashValue, pos_state: PosState, cs: &mut ChangeSet,
    ) -> Result<()> {
        diem_debug!("put_pos_state: {}", block_hash);
        cs.batch.put::<PosStateSchema>(block_hash, &pos_state)?;

        // replace pos state later to avoid clone.
        if self.latest_pos_state.load().current_view()
            < pos_state.current_view()
        {
            self.latest_pos_state.store(Arc::new(pos_state));
        }
        Ok(())
    }

    pub fn delete_pos_state(&self, block_hash: &HashValue) -> Result<()> {
        let mut cs = ChangeSet::new();
        cs.batch.delete::<PosStateSchema>(block_hash)?;
        self.db.write_schemas(cs.batch, true)
    }

    /// Read LedgerInfo by block id from the database.
    pub fn get_block_ledger_info(
        &self, consensus_block_id: &HashValue,
    ) -> Result<LedgerInfoWithSignatures> {
        self.db
            .get::<LedgerInfoByBlockSchema>(consensus_block_id)?
            .ok_or_else(|| {
                DiemDbError::NotFound(format!(
                    "LedgerInfo of block {}",
                    consensus_block_id
                ))
                .into()
            })
    }

    pub fn get_root_hash(&self, version: Version) -> Result<HashValue> {
        Accumulator::get_root_hash(self, version + 1)
    }

    pub fn get_latest_pos_state(&self) -> Arc<PosState> {
        self.latest_pos_state.load().clone()
    }

    pub fn put_reward_event(
        &self, epoch: u64, event: &RewardDistributionEvent,
    ) -> Result<()> {
        let mut cs = ChangeSet::new();
        cs.batch.put::<RewardEventSchema>(&epoch, event)?;
        self.db.write_schemas(cs.batch, false)
    }

    pub fn get_reward_event(
        &self, epoch: u64,
    ) -> Result<RewardDistributionEvent> {
        self.db.get::<RewardEventSchema>(&epoch)?.ok_or_else(|| {
            DiemDbError::NotFound(format!("RewardEvent of epoch {}", epoch))
                .into()
        })
    }

    pub fn put_committed_block(
        &self, block: &CommittedBlock, cs: &mut ChangeSet,
    ) -> Result<()> {
        diem_trace!("put_committed_block {:?}", block);
        cs.batch.put::<CommittedBlockSchema>(&block.hash, block)?;
        if !block.is_skipped {
            cs.batch
                .put::<CommittedBlockByViewSchema>(&block.view, &block.hash)?;
        }
        Ok(())
    }

    pub fn get_committed_block_by_hash(
        &self, block_hash: &HashValue,
    ) -> Result<CommittedBlock> {
        self.db
            .get::<CommittedBlockSchema>(&block_hash)?
            .ok_or_else(|| {
                DiemDbError::NotFound(format!(
                    "committed block of id {}",
                    block_hash
                ))
                .into()
            })
    }

    pub fn put_ledger_info_by_voted_block(
        &self, voted_block_id: &HashValue,
        ledger_info: &LedgerInfoWithSignatures, cs: &mut ChangeSet,
    ) -> Result<()>
    {
        cs.batch
            .put::<LedgerInfoByVotedBlockSchema>(voted_block_id, ledger_info)?;
        Ok(())
    }

    pub fn get_ledger_info_by_voted_block(
        &self, voted_block_id: &HashValue,
    ) -> Result<LedgerInfoWithSignatures> {
        self.db
            .get::<LedgerInfoByVotedBlockSchema>(&voted_block_id)?
            .ok_or_else(|| {
                DiemDbError::NotFound(format!(
                    "ledger_info_by_voted_block of id {}",
                    voted_block_id
                ))
                .into()
            })
    }

    pub fn get_committed_block_hash_by_view(
        &self, view: u64,
    ) -> Result<HashValue> {
        self.db
            .get::<CommittedBlockByViewSchema>(&view)?
            .ok_or_else(|| {
                DiemDbError::NotFound(format!(
                    "committed block of view {}",
                    view
                ))
                .into()
            })
    }
}

pub(crate) type Accumulator =
    MerkleAccumulator<LedgerStore, TransactionAccumulatorHasher>;

impl HashReader for LedgerStore {
    fn get(&self, position: Position) -> Result<HashValue> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| format_err!("{} does not exist.", position))
    }
}

pub struct TransactionInfoIter<'a> {
    inner: SchemaIterator<'a, TransactionInfoSchema>,
    expected_next_version: Version,
    end_version: Version,
}

impl<'a> TransactionInfoIter<'a> {
    fn next_impl(&mut self) -> Result<Option<TransactionInfo>> {
        if self.expected_next_version >= self.end_version {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((version, transaction_info)) => {
                ensure!(
                    version == self.expected_next_version,
                    "Transaction info versions are not consecutive.",
                );
                self.expected_next_version += 1;
                Some(transaction_info)
            }
            _ => None,
        };

        Ok(ret)
    }
}

impl<'a> Iterator for TransactionInfoIter<'a> {
    type Item = Result<TransactionInfo>;

    fn next(&mut self) -> Option<Self::Item> { self.next_impl().transpose() }
}

pub struct EpochEndingLedgerInfoIter<'a> {
    inner: SchemaIterator<'a, LedgerInfoSchema>,
    next_epoch: u64,
    end_epoch: u64,
}

impl<'a> EpochEndingLedgerInfoIter<'a> {
    fn next_impl(&mut self) -> Result<Option<LedgerInfoWithSignatures>> {
        if self.next_epoch >= self.end_epoch {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((epoch, li)) => {
                if !li.ledger_info().ends_epoch() {
                    None
                } else {
                    ensure!(
                        epoch == self.next_epoch,
                        "Epochs are not consecutive."
                    );
                    self.next_epoch += 1;
                    Some(li)
                }
            }
            _ => None,
        };

        Ok(ret)
    }
}

impl<'a> Iterator for EpochEndingLedgerInfoIter<'a> {
    type Item = Result<LedgerInfoWithSignatures>;

    fn next(&mut self) -> Option<Self::Item> { self.next_impl().transpose() }
}

#[cfg(test)]
mod ledger_info_test;
#[cfg(test)]
mod transaction_info_test;
