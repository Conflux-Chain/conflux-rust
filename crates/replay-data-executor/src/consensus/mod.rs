//! Replay executor: drive Conflux EVM execution over decoded packets and verify
//! each epoch's commitment against the chain.
//!
//! The implementation is split by responsibility across this module's children:
//! - [`setup`]      — construction, genesis seeding, checkpoint export/restore
//! - [`execution`]  — per-epoch / per-block EVM execution
//! - [`settlement`] — block + transaction-fee reward settlement
//! - [`commitment`] — commitment comparison, height math, memory windows
//!
//! All four operate on the same [`Replayer`]; inherent methods resolve
//! across the split `impl` blocks, so only free items cross module lines.

use anyhow::{ensure, Result};
use cfxpack::{
    decode::decode_packet_ext,
    packet::{Block, Packet, FLAG_PIVOT, FLAG_SKIPPED_EXECUTION},
};
use cfx_config::Configuration;
use cfx_executor::machine::Machine;
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_storage::StorageManager;
use cfx_types::H256;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;

mod commitment;
mod drive;
mod settlement;
mod setup;

pub(crate) use commitment::{EpochCommitment, ExecutedEpoch};

#[derive(Debug, Clone)]
pub struct Config {
    pub config_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub epoch_count: usize,
    pub block_count: usize,
    pub transaction_count: usize,
    pub receipts_root_prefix_matches: usize,
    pub logs_bloom_prefix_matches: usize,
    pub state_root_prefix_matches: usize,
    pub epochs: Vec<EpochReport>,
}

#[derive(Debug, Clone)]
pub struct EpochReport {
    pub pivot_height: u64,
    pub deferred_height: u64,
    pub pivot_hash: H256,
    pub pivot_timestamp: u64,
    pub block_count: usize,
    pub transaction_count: usize,
    pub computed_state_root: H256,
    pub expected_state_root_prefix: [u8; 4],
    pub state_root_prefix_match: bool,
    pub computed_receipts_root: H256,
    pub expected_receipts_root_prefix: [u8; 4],
    pub receipts_root_prefix_match: bool,
    pub computed_logs_bloom_hash: H256,
    pub expected_logs_bloom_hash_prefix: [u8; 4],
    pub logs_bloom_prefix_match: bool,
}

pub struct Replayer {
    conf: Configuration,
    _temp_dir: Option<TempDir>,
    // Still used to build genesis under both backends; under the minimal-mpt
    // backend it is not consulted again after construction.
    #[cfg_attr(feature = "backend-minimal-mpt", allow(dead_code))]
    storage_manager: Arc<StorageManager>,
    machine: Arc<Machine>,
    #[cfg_attr(feature = "backend-minimal-mpt", allow(dead_code))]
    snapshot_epoch_count: u32,
    previous_epoch_hash: H256,
    previous_epoch_pos_view: Option<u64>,
    previous_epoch_finalized_epoch: Option<u64>,
    previous_state_root: StateRootWithAuxInfo,
    commitments_by_height: BTreeMap<u64, EpochCommitment>,
    executed_epochs_by_height: BTreeMap<u64, ExecutedEpoch>,
    // Under the minimal-mpt backend, the single latest state shared across
    // epochs, seeded from the genesis dump. The cfx-storage `storage_manager`
    // above is still used to build genesis; only the per-epoch execution state
    // comes from here instead.
    #[cfg(feature = "backend-minimal-mpt")]
    minimal_backend: crate::minimal_backend::MinimalBackend,
}

impl Replayer {
    pub fn execute_packet(&mut self, packet: &[u8]) -> Result<RunReport> {
        let pos_h = self.conf.raw_conf.pos_reference_enable_height;
        let input = decode_packet_ext(packet, pos_h)?;
        self.execute_input(&input)
    }

    pub fn execute_input(&mut self, input: &Packet) -> Result<RunReport> {
        ensure!(!input.blocks.is_empty(), "packet has no blocks");
        // Strip the epoch skipped-set blocks once, here at the input boundary.
        // Consensus never executes, numbers, rewards, or receipts them — they
        // are carried in the packet only for transaction recycling — so the rest
        // of the executor only ever sees the executed set and never has to
        // re-check the skipped flag.
        let blocks: Vec<&Block> = input
            .blocks
            .iter()
            .filter(|block| block.flags & FLAG_SKIPPED_EXECUTION == 0)
            .collect();
        ensure!(!blocks.is_empty(), "packet has no executed blocks");
        let mut epochs = Vec::new();
        let mut start = 0usize;
        let mut next_block_number = input.first_block_number;
        while start < blocks.len() {
            let Some(relative_pivot) = blocks[start..]
                .iter()
                .position(|block| block.flags & FLAG_PIVOT != 0)
            else {
                anyhow::bail!("epoch group has no pivot block");
            };
            let end = start + relative_pivot;
            let epoch_blocks = &blocks[start..=end];
            epochs.push(self.execute_epoch(epoch_blocks, next_block_number)?);
            next_block_number += epoch_blocks.len() as u64;
            start = end + 1;
        }

        let block_count = blocks.len();
        let transaction_count = blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum();
        Ok(RunReport {
            epoch_count: epochs.len(),
            block_count,
            transaction_count,
            receipts_root_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.receipts_root_prefix_match)
                .count(),
            logs_bloom_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.logs_bloom_prefix_match)
                .count(),
            state_root_prefix_matches: epochs
                .iter()
                .filter(|epoch| epoch.state_root_prefix_match)
                .count(),
            epochs,
        })
    }

}
