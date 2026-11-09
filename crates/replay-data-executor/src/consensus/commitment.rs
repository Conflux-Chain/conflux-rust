//! Per-epoch commitments, the prefix comparison against the chain, the
//! deferred/finalized height math, and the bounded-memory windows.

use super::Replayer;
use cfxpack::packet::Block;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT, consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_types::H256;
use primitives::BlockHeaderBuilder;
#[cfg(not(feature = "backend-minimal-mpt"))]
use primitives::receipt::BlockReceipts;
use std::collections::BTreeMap;
#[cfg(not(feature = "backend-minimal-mpt"))]
use std::sync::Arc;

#[cfg(feature = "backend-minimal-mpt")]
pub(crate) use cfx_replay_checkpoint::{EpochCommitment, ExecutedEpoch};

/// The commitment an epoch produces: the three roots we recompute and later
/// compare (DEFERRED_STATE_EPOCH_COUNT epochs on) against the chain's pivot.
#[cfg(not(feature = "backend-minimal-mpt"))]
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochCommitment {
    pub(crate) state_root: H256,
    pub(crate) receipts_root: H256,
    pub(crate) logs_bloom_hash: H256,
}

/// One executed epoch retained until its reward settles REWARD_EPOCH_COUNT
/// epochs later.
#[cfg(not(feature = "backend-minimal-mpt"))]
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

/// Compute the folded commitment for a blaming pivot at `height` with
/// `blame = k > 0`. The fold covers heights `height..=height-k` (own root
/// first), producing the keccak right-fold that a valid blaming header
/// carries as its deferred commitment. Returns `None` if any needed
/// commitment is missing from the map (caller treats as mismatch).
pub(super) fn folded_blame_commitment(
    commitments: &BTreeMap<u64, EpochCommitment>,
    height: u64,
    blame: u64,
) -> Option<EpochCommitment> {
    let mut state_roots = Vec::with_capacity(blame as usize + 1);
    let mut receipts_roots = Vec::with_capacity(blame as usize + 1);
    let mut bloom_hashes = Vec::with_capacity(blame as usize + 1);

    for j in 0..=blame {
        let h = height.checked_sub(j)?;
        let dh = deferred_commitment_height(h);
        let c = commitments.get(&dh)?;
        state_roots.push(c.state_root);
        receipts_roots.push(c.receipts_root);
        bloom_hashes.push(c.logs_bloom_hash);
    }

    Some(EpochCommitment {
        state_root: BlockHeaderBuilder::compute_blame_state_root_vec_root(state_roots),
        receipts_root: BlockHeaderBuilder::compute_blame_state_root_vec_root(receipts_roots),
        logs_bloom_hash: BlockHeaderBuilder::compute_blame_state_root_vec_root(bloom_hashes),
    })
}

impl Replayer {
    /// Bound memory: a commitment is only re-read DEFERRED_STATE_EPOCH_COUNT
    /// epochs later and an executed epoch only REWARD_EPOCH_COUNT epochs later,
    /// so older entries are dead. Without this the maps grow with the chain
    /// length and a full-chain replay exhausts memory.
    ///
    /// The commitment floor is lowered when a recent blamed/mismatched run
    /// means an older commitment may still be needed for fold verification:
    /// `min(normal_floor, last_ok_height - DEFERRED_STATE_EPOCH_COUNT - 1)`.
    pub(super) fn prune_old_state(&mut self, pivot_height: u64) {
        let normal_floor =
            pivot_height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT + 1);
        let safe_floor = self
            .last_verified_ok_height
            .map(|h| h.saturating_sub(DEFERRED_STATE_EPOCH_COUNT + 1))
            .unwrap_or(0);
        let commitment_floor = normal_floor.min(safe_floor);
        self.commitments_by_height =
            self.commitments_by_height.split_off(&commitment_floor);
        let reward_floor = pivot_height.saturating_sub(REWARD_EPOCH_COUNT + 1);
        self.executed_epochs_by_height =
            self.executed_epochs_by_height.split_off(&reward_floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::H256;

    fn h(n: u64) -> H256 {
        H256::from_low_u64_be(n)
    }

    fn commitment(n: u64) -> EpochCommitment {
        EpochCommitment {
            state_root: h(n * 3),
            receipts_root: h(n * 3 + 1),
            logs_bloom_hash: h(n * 3 + 2),
        }
    }

    #[test]
    fn fold_k1_matches_manual_keccak() {
        let mut map = BTreeMap::new();
        // height=10, blame=1 → fold deferred heights 5 and 4.
        // (DEFERRED_STATE_EPOCH_COUNT = 5)
        map.insert(5, commitment(5));
        map.insert(4, commitment(4));

        let folded = folded_blame_commitment(&map, 10, 1).unwrap();

        let expected_state = BlockHeaderBuilder::compute_blame_state_root_vec_root(
            vec![commitment(5).state_root, commitment(4).state_root],
        );
        assert_eq!(folded.state_root, expected_state);
    }

    #[test]
    fn fold_k0_degenerates_to_single_root() {
        let mut map = BTreeMap::new();
        map.insert(5, commitment(5));

        let folded = folded_blame_commitment(&map, 10, 0).unwrap();
        assert_eq!(folded.state_root, commitment(5).state_root);
    }

    #[test]
    fn fold_missing_commitment_returns_none() {
        let map = BTreeMap::new(); // empty
        assert!(folded_blame_commitment(&map, 10, 1).is_none());
    }

    #[test]
    fn fold_low_height_saturates() {
        let mut map = BTreeMap::new();
        // height=3, blame=1 → deferred heights 0 and 0 (saturating_sub).
        // Both map to the same key (0), so the fold gets [c(0), c(0)].
        map.insert(0, commitment(0));
        let folded = folded_blame_commitment(&map, 3, 1);
        // height=3, j=0 → deferred_height=3-5=0 (saturated). j=1 → h=2, deferred=0.
        assert!(folded.is_some());
    }

    #[test]
    fn fold_height_underflow_returns_none() {
        let map = BTreeMap::new();
        // height=0, blame=1 → h=0-1 underflows
        assert!(folded_blame_commitment(&map, 0, 1).is_none());
    }
}
