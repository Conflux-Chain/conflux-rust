//! Checkpoint / resume for the minimal-mpt replay backend.
//!
//! A full-chain replay starts from genesis and can run for a very long time;
//! an unplanned crash (or a planned stop) should not throw away all progress.
//! This module captures a *resumable* snapshot of the executor at a 2000-epoch
//! (snapshot-rotation) boundary and reloads it so the next run continues from
//! the middle instead of from genesis.
//!
//! ## What has to be captured, and why
//!
//! The minimal-mpt trie is latest-only, but the replay carries two short
//! rolling windows of *executor* metadata that the trie knows nothing about:
//!
//! - `commitments[H-5 ..= H]` — deferred state/receipts/logs commitments are
//!   compared 5 epochs late.
//! - `executed_epochs[H-12 ..= H]` — block rewards / fees are settled 12 epochs
//!   late, and that settlement needs each epoch's **execution receipts**
//!   (gas_fee / burnt_gas_fee / secondary_reward). Receipts are an execution
//!   product, absent from the packets, and cannot be recomputed without the
//!   state from 12 epochs earlier (which latest-only does not keep). So the
//!   window must travel with the checkpoint.
//!
//! These windows are tiny (≤12 epochs of blocks+receipts) next to the snapshot.
//!
//! ## Separation of concerns
//!
//! The trie half reuses minimal-mpt's own [`PersistedState`] (which already
//! derives `Serialize`) — this layer never touches trie internals. The only
//! bespoke encoding here is for [`BlockReceipts`], which has no serde but does
//! have RLP (the very encoding the chain uses for its receipts root); we store
//! the RLP bytes. The executor exposes `save_checkpoint_streaming` /
//! `restore_streaming`; the execution main loop and the packet codec are
//! untouched.

mod load;
mod save;
#[cfg(test)]
mod tests;
mod verify;

use crate::consensus::{EpochCommitment, ExecutedEpoch};
use anyhow::{Context, Result};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_minimal_mpt::{PersistedState, State as MmptState};
use cfx_types::H256;
use primitives::receipt::BlockReceipts;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

pub(crate) use save::CheckpointParts;

/// The executor state reconstructed from a checkpoint, with the trie half
/// already built into a live `State` (never routed through a fully-materialized
/// `PersistedState`). This is what `load_streaming` yields — the streaming
/// counterpart to `into_parts`.
pub struct RestoredCheckpoint {
    pub state: MmptState,
    pub height: u64,
    pub previous_epoch_hash: H256,
    pub previous_state_root: StateRootWithAuxInfo,
    pub previous_epoch_pos_view: Option<u64>,
    pub previous_epoch_finalized_epoch: Option<u64>,
    pub commitments: BTreeMap<u64, EpochCommitment>,
    pub executed_epochs: BTreeMap<u64, ExecutedEpoch>,
}

/// Bumped if the on-disk layout changes incompatibly.
pub(crate) const CHECKPOINT_VERSION: u32 = 2;

/// One executed epoch as stored on disk. Blocks serde directly; receipts are
/// RLP-encoded (they have no serde, only RLP) — one byte string per block.
#[derive(Clone, Serialize, Deserialize)]
struct ExecutedEpochDisk {
    blocks: Vec<cfxpack::packet::Block>,
    receipts_rlp: Vec<Vec<u8>>,
}

impl ExecutedEpochDisk {
    fn from_live(data: &ExecutedEpoch) -> Self {
        Self {
            blocks: data.blocks.clone(),
            receipts_rlp: data
                .receipts
                .iter()
                .map(|r| rlp::encode(&**r).to_vec())
                .collect(),
        }
    }

    fn into_live(self) -> Result<ExecutedEpoch> {
        let receipts = self
            .receipts_rlp
            .iter()
            .map(|bytes| {
                rlp::decode::<BlockReceipts>(bytes)
                    .map(Arc::new)
                    .context("decode checkpoint receipts (RLP)")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ExecutedEpoch {
            blocks: self.blocks,
            receipts,
        })
    }
}

#[derive(Deserialize)]
struct CheckpointV1 {
    #[allow(dead_code)]
    version: u32,
    height: u64,
    mmpt: PersistedState,
    previous_epoch_hash: H256,
    previous_state_root: StateRootWithAuxInfo,
    commitments: Vec<(u64, EpochCommitment)>,
    executed_epochs: Vec<(u64, ExecutedEpochDisk)>,
}

impl CheckpointV1 {
    fn upgrade(self) -> Checkpoint {
        Checkpoint {
            version: CHECKPOINT_VERSION,
            height: self.height,
            mmpt: self.mmpt,
            previous_epoch_hash: self.previous_epoch_hash,
            previous_state_root: self.previous_state_root,
            previous_epoch_pos_view: None,
            previous_epoch_finalized_epoch: None,
            commitments: self.commitments,
            executed_epochs: self.executed_epochs,
        }
    }
}

/// A self-contained, resumable snapshot of the replay executor.
#[derive(Serialize, Deserialize)]
pub struct Checkpoint {
    version: u32,
    /// Committed height (== last pivot height) this checkpoint sits at.
    height: u64,
    /// Reused minimal-mpt trie snapshot — the "native" persistence half.
    mmpt: PersistedState,
    previous_epoch_hash: H256,
    previous_state_root: StateRootWithAuxInfo,
    previous_epoch_pos_view: Option<u64>,
    previous_epoch_finalized_epoch: Option<u64>,
    commitments: Vec<(u64, EpochCommitment)>,
    executed_epochs: Vec<(u64, ExecutedEpochDisk)>,
}

impl Checkpoint {
    /// Assemble a checkpoint from the executor's live pieces. `mmpt` comes from
    /// `MinimalBackend::export_persisted()` (so its `height` is authoritative).
    pub fn build(
        mmpt: PersistedState, previous_epoch_hash: H256,
        previous_state_root: &StateRootWithAuxInfo,
        previous_epoch_pos_view: Option<u64>,
        previous_epoch_finalized_epoch: Option<u64>,
        commitments: &BTreeMap<u64, EpochCommitment>,
        executed_epochs: &BTreeMap<u64, ExecutedEpoch>,
    ) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            height: mmpt.height,
            mmpt,
            previous_epoch_hash,
            previous_state_root: previous_state_root.clone(),
            previous_epoch_pos_view,
            previous_epoch_finalized_epoch,
            commitments: commitments.iter().map(|(h, c)| (*h, *c)).collect(),
            executed_epochs: executed_epochs
                .iter()
                .map(|(h, d)| (*h, ExecutedEpochDisk::from_live(d)))
                .collect(),
        }
    }

    /// The committed height this checkpoint resumes from.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Decompose back into the executor's live fields (RLP-decoding receipts).
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> Result<(
        PersistedState,
        H256,
        StateRootWithAuxInfo,
        Option<u64>,
        Option<u64>,
        BTreeMap<u64, EpochCommitment>,
        BTreeMap<u64, ExecutedEpoch>,
    )> {
        let commitments = self.commitments.into_iter().collect();
        let mut executed_epochs = BTreeMap::new();
        for (h, disk) in self.executed_epochs {
            executed_epochs.insert(h, disk.into_live()?);
        }
        Ok((
            self.mmpt,
            self.previous_epoch_hash,
            self.previous_state_root,
            self.previous_epoch_pos_view,
            self.previous_epoch_finalized_epoch,
            commitments,
            executed_epochs,
        ))
    }
}
