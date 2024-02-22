// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[cfg(test)]
mod consensusdb_test;
mod schema;

use crate::pos::consensus::{
    consensusdb::schema::{
        block::BlockSchema,
        ledger_block::LedgerBlockSchema,
        quorum_certificate::QCSchema,
        single_entry::{SingleEntryKey, SingleEntrySchema},
        staking_event::StakingEventsSchema,
        STAKING_EVENTS_CF_NAME,
    },
    error::DbError,
};
use anyhow::{anyhow, Result};
use cfx_types::H256;
use consensus_types::{
    block::Block, db::LedgerBlockRW, quorum_cert::QuorumCert,
};
use diem_crypto::HashValue;
use diem_logger::prelude::*;
use diem_types::block_info::PivotBlockDecision;
use pow_types::StakingEvent;
use schema::{
    BLOCK_CF_NAME, LEDGER_BLOCK_CF_NAME, QC_CF_NAME, SINGLE_ENTRY_CF_NAME,
};
use schemadb::{Options, ReadOptions, SchemaBatch, DB, DEFAULT_CF_NAME};
use std::{collections::HashMap, iter::Iterator, path::Path, time::Instant};

/// ConsensusDB
pub struct ConsensusDB {
    db: DB,
}

impl ConsensusDB {
    /// new
    pub fn new<P: AsRef<Path> + Clone>(db_root_path: P) -> Self {
        let column_families = vec![
            /* UNUSED CF = */ DEFAULT_CF_NAME,
            BLOCK_CF_NAME,
            QC_CF_NAME,
            SINGLE_ENTRY_CF_NAME,
            LEDGER_BLOCK_CF_NAME,
            STAKING_EVENTS_CF_NAME,
        ];

        let path = db_root_path.as_ref().join("consensusdb");
        let instant = Instant::now();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open(path.clone(), "consensus", column_families, opts)
            .expect("ConsensusDB open failed; unable to continue");

        diem_info!(
            "Opened ConsensusDB at {:?} in {} ms",
            path,
            instant.elapsed().as_millis()
        );

        Self { db }
    }

    /// get_data
    pub fn get_data(
        &self,
    ) -> Result<(
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<Block>,
        Vec<QuorumCert>,
    )> {
        let last_vote = self.get_last_vote()?;
        let highest_timeout_certificate =
            self.get_highest_timeout_certificate()?;
        let consensus_blocks = self
            .get_blocks()?
            .into_iter()
            .map(|(_block_hash, block_content)| block_content)
            .collect::<Vec<_>>();
        let consensus_qcs = self
            .get_quorum_certificates()?
            .into_iter()
            .map(|(_block_hash, qc)| qc)
            .collect::<Vec<_>>();
        Ok((
            last_vote,
            highest_timeout_certificate,
            consensus_blocks,
            consensus_qcs,
        ))
    }

    /// save_highest_timeout_certificate
    pub fn save_highest_timeout_certificate(
        &self, highest_timeout_certificate: Vec<u8>,
    ) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(
            &SingleEntryKey::HighestTimeoutCertificate,
            &highest_timeout_certificate,
        )?;
        self.commit(batch, false)?;
        Ok(())
    }

    /// save_vote
    pub fn save_vote(&self, last_vote: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(
            &SingleEntryKey::LastVoteMsg,
            &last_vote,
        )?;
        self.commit(batch, false)
    }

    /// save_blocks_and_quorum_certificates
    pub fn save_blocks_and_quorum_certificates(
        &self, block_data: Vec<Block>, qc_data: Vec<QuorumCert>,
    ) -> Result<(), DbError> {
        if block_data.is_empty() && qc_data.is_empty() {
            return Err(anyhow::anyhow!(
                "Consensus block and qc data is empty!"
            )
            .into());
        }
        let mut batch = SchemaBatch::new();
        block_data.iter().try_for_each(|block| {
            batch.put::<BlockSchema>(&block.id(), block)
        })?;
        qc_data.iter().try_for_each(|qc| {
            batch.put::<QCSchema>(&qc.certified_block().id(), qc)
        })?;
        self.commit(batch, false)
    }

    /// delete_blocks_and_quorum_certificates
    pub fn delete_blocks_and_quorum_certificates(
        &self, block_ids: Vec<HashValue>,
    ) -> Result<(), DbError> {
        if block_ids.is_empty() {
            return Err(anyhow::anyhow!("Consensus block ids is empty!").into());
        }
        let mut batch = SchemaBatch::new();
        block_ids.iter().try_for_each(|hash| {
            batch.delete::<BlockSchema>(hash)?;
            batch.delete::<QCSchema>(hash)
        })?;
        self.commit(batch, false)
    }

    /// Write the whole schema batch including all data necessary to mutate the
    /// ledger state of some transaction by leveraging rocksdb atomicity
    /// support.
    fn commit(
        &self, batch: SchemaBatch, fast_write: bool,
    ) -> Result<(), DbError> {
        self.db.write_schemas(batch, fast_write)?;
        Ok(())
    }

    /// Get latest timeout certificates (we only store the latest highest
    /// timeout certificates).
    fn get_highest_timeout_certificate(
        &self,
    ) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self.db.get::<SingleEntrySchema>(
            &SingleEntryKey::HighestTimeoutCertificate,
        )?)
    }

    /// Delete the timeout certificates
    pub fn delete_highest_timeout_certificate(&self) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.delete::<SingleEntrySchema>(
            &SingleEntryKey::HighestTimeoutCertificate,
        )?;
        self.commit(batch, false)
    }

    /// Get serialized latest vote (if available)
    fn get_last_vote(&self) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self
            .db
            .get::<SingleEntrySchema>(&SingleEntryKey::LastVoteMsg)?)
    }

    /// delete_last_vote_msg
    pub fn delete_last_vote_msg(&self) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.delete::<SingleEntrySchema>(&SingleEntryKey::LastVoteMsg)?;
        self.commit(batch, false)?;
        Ok(())
    }

    /// Get all consensus blocks.
    pub fn get_blocks(&self) -> Result<HashMap<HashValue, Block>, DbError> {
        let mut iter = self.db.iter::<BlockSchema>(ReadOptions::default())?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<HashMap<HashValue, Block>>>()?)
    }

    /// Get all consensus QCs.
    pub fn get_quorum_certificates(
        &self,
    ) -> Result<HashMap<HashValue, QuorumCert>, DbError> {
        let mut iter = self.db.iter::<QCSchema>(ReadOptions::default())?;
        iter.seek_to_first();
        Ok(iter.collect::<Result<HashMap<HashValue, QuorumCert>>>()?)
    }

    /// Save pow staking events.
    pub fn put_staking_events(
        &self, pow_epoch_number: u64, pow_epoch_hash: H256,
        events: Vec<StakingEvent>,
    ) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<StakingEventsSchema>(
            &pow_epoch_number,
            &(events, pow_epoch_hash),
        )?;
        self.commit(batch, true)
    }

    /// Save staking events between two pivot decisions.
    pub fn get_staking_events(
        &self, parent_decision: PivotBlockDecision,
        me_decision: PivotBlockDecision,
    ) -> Result<Vec<StakingEvent>, DbError> {
        diem_debug!(
            "consensusdb::get_staking_events: parent={:?} me={:?}",
            parent_decision,
            me_decision
        );
        if parent_decision == me_decision {
            return Ok(vec![]);
        }
        if me_decision.height <= parent_decision.height {
            return Err(anyhow!("only forward querying allowed").into());
        }
        let mut read_opt = ReadOptions::default();
        // lower bound is inclusive
        read_opt.set_iterate_lower_bound(
            parent_decision.height.to_be_bytes().to_vec(),
        );
        // upper bound is exclusive
        read_opt.set_iterate_upper_bound(
            (me_decision.height + 1).to_be_bytes().to_vec(),
        );
        let mut staking_events = Vec::with_capacity(
            (me_decision.height - parent_decision.height + 1) as usize,
        );
        let mut iter = self.db.iter::<StakingEventsSchema>(read_opt)?;
        iter.seek_to_first();
        let mut expected_epoch_number = parent_decision.height;
        for element in iter {
            let (pow_epoch_number, (mut events, pow_epoch_hash)) = element?;
            if pow_epoch_number != expected_epoch_number {
                return Err(anyhow!(
                    "skipped staking events, expected={}, get={}",
                    expected_epoch_number,
                    pow_epoch_number
                )
                .into());
            }
            if pow_epoch_number == parent_decision.height
                && pow_epoch_hash != parent_decision.block_hash
            {
                return Err(anyhow!("inconsistent parent epoch hash, height={} expected={:?}, get={:?}", pow_epoch_number, parent_decision.block_hash, pow_epoch_hash).into());
            }
            if pow_epoch_number == me_decision.height
                && pow_epoch_hash != me_decision.block_hash
            {
                return Err(anyhow!("inconsistent me epoch hash, height={} expected={:?}, get={:?}", pow_epoch_number, me_decision.block_hash, pow_epoch_hash).into());
            }
            if pow_epoch_number != parent_decision.height {
                // Skip the events in parent_decision since they are in the
                // previous pos block.
                staking_events.append(&mut events);
            }
            expected_epoch_number += 1;
        }
        if expected_epoch_number != me_decision.height + 1 {
            return Err(anyhow!(
                "incomplete staking events, reach height={} me_decision={:?}",
                expected_epoch_number,
                me_decision
            )
            .into());
        }
        diem_debug!(
            "consensusdb::get_staking_events returns len={} ",
            staking_events.len()
        );
        Ok(staking_events)
    }

    /// Delete all staking events before an PoW epoch number after we have
    /// committed a PoS block that processes this PoW pivot decision.
    pub fn delete_staking_events_before(
        &self, committed_pow_epoch_number: u64,
    ) -> Result<(), DbError> {
        self.db
            .range_delete::<StakingEventsSchema, u64>(
                &0,
                &committed_pow_epoch_number,
            )
            .map_err(|e| e.into())
    }
}

impl LedgerBlockRW for ConsensusDB {
    /// get_ledger_block
    fn get_ledger_block(&self, block_id: &HashValue) -> Result<Option<Block>> {
        Ok(self.db.get::<LedgerBlockSchema>(block_id)?)
    }

    /// save_ledger_blocks
    fn save_ledger_blocks(&self, blocks: Vec<Block>) -> Result<()> {
        let mut batch = SchemaBatch::new();
        for block in blocks {
            batch.put::<LedgerBlockSchema>(&block.id(), &block)?;
        }
        Ok(self.commit(batch, true)?)
    }

    /// Get qc for not committed blocks.
    fn get_qc_for_block(
        &self, block_id: &HashValue,
    ) -> Result<Option<QuorumCert>> {
        Ok(self.db.get::<QCSchema>(block_id)?)
    }
}
