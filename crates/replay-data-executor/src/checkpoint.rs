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
//! the RLP bytes. The executor exposes only `export_checkpoint` / `restore`;
//! the execution main loop and the packet codec are untouched.

use crate::consensus::{EpochCommitment, ExecutedEpoch};
use anyhow::{Context, Result};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_minimal_mpt::PersistedState;
use cfx_types::H256;
use primitives::receipt::BlockReceipts;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::Arc,
};

/// Bumped if the on-disk layout changes incompatibly.
const CHECKPOINT_VERSION: u32 = 1;

/// One executed epoch as stored on disk. Blocks serde directly; receipts are
/// RLP-encoded (they have no serde, only RLP) — one byte string per block.
#[derive(Serialize, Deserialize)]
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
    commitments: Vec<(u64, EpochCommitment)>,
    executed_epochs: Vec<(u64, ExecutedEpochDisk)>,
}

impl Checkpoint {
    /// Assemble a checkpoint from the executor's live pieces. `mmpt` comes from
    /// `MinimalBackend::export_persisted()` (so its `height` is authoritative).
    pub(crate) fn build(
        mmpt: PersistedState,
        previous_epoch_hash: H256,
        previous_state_root: &StateRootWithAuxInfo,
        commitments: &BTreeMap<u64, EpochCommitment>,
        executed_epochs: &BTreeMap<u64, ExecutedEpoch>,
    ) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            height: mmpt.height,
            mmpt,
            previous_epoch_hash,
            previous_state_root: previous_state_root.clone(),
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
    pub(crate) fn into_parts(
        self,
    ) -> Result<(
        PersistedState,
        H256,
        StateRootWithAuxInfo,
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
            commitments,
            executed_epochs,
        ))
    }

    /// Atomically write the checkpoint (tmp + rename, like minimal-mpt's
    /// `FileStore`), so a crash mid-write never leaves a torn file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let bytes = bincode::serialize(self)
            .context("serialize replay checkpoint")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create checkpoint dir {}", parent.display()))?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &bytes)
            .with_context(|| format!("write checkpoint tmp {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("rename checkpoint into {}", path.display()))?;
        Ok(())
    }

    /// Load a checkpoint if one exists at `path`; `Ok(None)` when absent.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)
            .with_context(|| format!("read checkpoint {}", path.display()))?;
        let ckpt: Self = bincode::deserialize(&bytes)
            .with_context(|| format!("deserialize checkpoint {}", path.display()))?;
        anyhow::ensure!(
            ckpt.version == CHECKPOINT_VERSION,
            "checkpoint version mismatch: file v{}, expected v{}",
            ckpt.version,
            CHECKPOINT_VERSION,
        );
        Ok(Some(ckpt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::U256;

    fn h(b: u8) -> H256 {
        H256([b; 32])
    }

    /// build → save → load → into_parts reproduces every field, including the
    /// RLP-encoded receipts window and the reused minimal-mpt snapshot.
    #[test]
    fn checkpoint_roundtrips_through_disk() {
        let mut mmpt = PersistedState::default();
        mmpt.height = 4000;

        let mut commitments = BTreeMap::new();
        commitments.insert(
            3998u64,
            EpochCommitment {
                state_root: h(1),
                receipts_root: h(2),
                logs_bloom_hash: h(3),
            },
        );
        commitments.insert(
            4000u64,
            EpochCommitment {
                state_root: h(4),
                receipts_root: h(5),
                logs_bloom_hash: h(6),
            },
        );

        let receipts = vec![Arc::new(BlockReceipts {
            receipts: vec![],
            block_number: 12345,
            secondary_reward: U256::from(777u64),
            tx_execution_error_messages: vec!["boom".to_string()],
        })];
        let mut executed = BTreeMap::new();
        executed.insert(
            4000u64,
            ExecutedEpoch {
                blocks: vec![],
                receipts,
            },
        );

        let prev_root = StateRootWithAuxInfo::genesis(&h(9));
        let ckpt = Checkpoint::build(
            mmpt,
            h(7),
            &prev_root,
            &commitments,
            &executed,
        );
        assert_eq!(ckpt.height(), 4000);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.bin");
        ckpt.save(&path).unwrap();
        let loaded = Checkpoint::load(&path).unwrap().unwrap();
        let (mmpt2, hash2, root2, commitments2, executed2) =
            loaded.into_parts().unwrap();

        assert_eq!(mmpt2.height, 4000);
        assert_eq!(hash2, h(7));
        assert_eq!(root2, prev_root);
        assert_eq!(commitments2.len(), 2);
        assert_eq!(commitments2[&4000].state_root, h(4));
        assert_eq!(commitments2[&3998].logs_bloom_hash, h(3));

        let r = &executed2[&4000].receipts[0];
        assert_eq!(r.block_number, 12345);
        assert_eq!(r.secondary_reward, U256::from(777u64));
        assert_eq!(r.tx_execution_error_messages, vec!["boom".to_string()]);
    }

    #[test]
    fn load_absent_checkpoint_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.bin");
        assert!(Checkpoint::load(&path).unwrap().is_none());
    }
}
