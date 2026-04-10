// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module provides mock dbreader for tests.

use crate::{DBReaderForPoW, DbReader, StartupInfo, TreeState};
use anyhow::Result;
use diem_crypto::HashValue;
use diem_types::{
    committed_block::CommittedBlock, contract_event::ContractEvent,
    epoch_change::EpochChangeProof, ledger_info::LedgerInfoWithSignatures,
    reward_distribution_event::RewardDistributionEventV2,
};

/// This is a mock of the dbreader in tests.
pub struct MockDbReader;

impl DbReader for MockDbReader {
    fn get_epoch_ending_ledger_infos(
        &self, _start_epoch: u64, _end_epoch: u64,
    ) -> Result<EpochChangeProof> {
        unimplemented!()
    }

    fn get_block_timestamp(&self, _version: u64) -> Result<u64> {
        unimplemented!()
    }

    /// Returns the latest ledger info.
    fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        unimplemented!()
    }

    fn get_startup_info(
        &self, _need_pos_state: bool,
    ) -> Result<Option<StartupInfo>> {
        unimplemented!()
    }

    fn get_latest_tree_state(&self) -> Result<TreeState> { unimplemented!() }

    fn get_epoch_ending_ledger_info(
        &self, _known_version: u64,
    ) -> Result<LedgerInfoWithSignatures> {
        unimplemented!()
    }
}

impl DBReaderForPoW for MockDbReader {
    fn get_latest_ledger_info_option(
        &self,
    ) -> Option<LedgerInfoWithSignatures> {
        todo!()
    }

    fn get_block_ledger_info(
        &self, _consensus_block_id: &HashValue,
    ) -> anyhow::Result<LedgerInfoWithSignatures> {
        todo!()
    }

    fn get_events_by_version(
        &self, _start_version: u64, _end_version: u64,
    ) -> anyhow::Result<Vec<ContractEvent>> {
        todo!()
    }

    fn get_epoch_ending_blocks(
        &self, _start_epoch: u64, _end_epoch: u64,
    ) -> anyhow::Result<Vec<HashValue>> {
        todo!()
    }

    fn get_reward_event(
        &self, _epoch: u64,
    ) -> anyhow::Result<RewardDistributionEventV2> {
        todo!()
    }

    fn get_committed_block_by_hash(
        &self, _block_hash: &HashValue,
    ) -> anyhow::Result<CommittedBlock> {
        todo!()
    }

    fn get_committed_block_hash_by_view(
        &self, _view: u64,
    ) -> Result<HashValue> {
        todo!()
    }

    fn get_ledger_info_by_voted_block(
        &self, _block_id: &HashValue,
    ) -> Result<LedgerInfoWithSignatures> {
        todo!()
    }

    fn get_block_hash_by_epoch_and_round(
        &self, _epoch: u64, _round: u64,
    ) -> Result<HashValue> {
        todo!()
    }
}
