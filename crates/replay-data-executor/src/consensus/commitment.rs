//! Per-epoch commitments, the prefix comparison against the chain, the
//! deferred/finalized height math, and the bounded-memory windows.

use super::Replayer;
use cfxpack::packet::Block;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT, consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_types::H256;
use primitives::receipt::BlockReceipts;
use std::sync::Arc;

/// The commitment an epoch produces: the three roots we recompute and later
/// compare (DEFERRED_STATE_EPOCH_COUNT epochs on) against the chain's pivot.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochCommitment {
    pub(crate) state_root: H256,
    pub(crate) receipts_root: H256,
    pub(crate) logs_bloom_hash: H256,
}

/// One executed epoch retained until its reward settles REWARD_EPOCH_COUNT
/// epochs later.
#[derive(Debug, Clone)]
pub(crate) struct ExecutedEpoch {
    pub(crate) blocks: Vec<Block>,
    pub(crate) receipts: Vec<Arc<BlockReceipts>>,
}

/// The on-chain expected 4-byte prefixes for a pivot, and whether the deferred
/// commitment we recomputed matches each of them. We compare only 4-byte
/// prefixes because the packet stores the chain's roots truncated.
pub(super) struct PrefixChecks {
    pub(super) expected_state_root_prefix: [u8; 4],
    pub(super) expected_receipts_root_prefix: [u8; 4],
    pub(super) expected_logs_bloom_hash_prefix: [u8; 4],
    pub(super) state_root_prefix_match: bool,
    pub(super) receipts_root_prefix_match: bool,
    pub(super) logs_bloom_prefix_match: bool,
}

pub(super) fn compare_commitment(
    deferred: &EpochCommitment, pivot: &Block,
) -> PrefixChecks {
    let expected_state_root_prefix = prefix4(pivot.deferred_state_root);
    let expected_receipts_root_prefix = prefix4(pivot.deferred_receipts_root);
    let expected_logs_bloom_hash_prefix = prefix4(pivot.deferred_logs_bloom_hash);
    PrefixChecks {
        state_root_prefix_match: prefix4(deferred.state_root) == expected_state_root_prefix,
        receipts_root_prefix_match: prefix4(deferred.receipts_root)
            == expected_receipts_root_prefix,
        logs_bloom_prefix_match: prefix4(deferred.logs_bloom_hash)
            == expected_logs_bloom_hash_prefix,
        expected_state_root_prefix,
        expected_receipts_root_prefix,
        expected_logs_bloom_hash_prefix,
    }
}

fn prefix4(hash: H256) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash.as_bytes()[..4]);
    out
}

/// The committed height whose commitment a pivot at `height` checks against.
pub(super) fn deferred_commitment_height(height: u64) -> u64 {
    height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT)
}

impl Replayer {
    /// Bound memory: a commitment is only re-read DEFERRED_STATE_EPOCH_COUNT
    /// epochs later and an executed epoch only REWARD_EPOCH_COUNT epochs later,
    /// so older entries are dead. Without this the maps grow with the chain
    /// length and a full-chain replay exhausts memory.
    pub(super) fn prune_old_state(&mut self, pivot_height: u64) {
        let commitment_floor =
            pivot_height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT + 1);
        self.commitments_by_height =
            self.commitments_by_height.split_off(&commitment_floor);
        let reward_floor = pivot_height.saturating_sub(REWARD_EPOCH_COUNT + 1);
        self.executed_epochs_by_height =
            self.executed_epochs_by_height.split_off(&reward_floor);
    }
}
