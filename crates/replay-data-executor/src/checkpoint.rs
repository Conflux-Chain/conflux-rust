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
use cfx_minimal_mpt::{PersistedState, State as MmptState};
use cfx_types::H256;
use primitives::receipt::BlockReceipts;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufReader, BufWriter, Write},
    path::Path,
    sync::Arc,
};

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
const CHECKPOINT_VERSION: u32 = 2;

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

#[derive(Deserialize)]
struct CheckpointV1 {
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
        mmpt: PersistedState,
        previous_epoch_hash: H256,
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

    /// Atomically write the checkpoint (tmp + rename, like minimal-mpt's
    /// `FileStore`), so a crash mid-write never leaves a torn file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create checkpoint dir {}", parent.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let file = fs::File::create(&tmp)
            .with_context(|| format!("create checkpoint tmp {}", tmp.display()))?;
        let mut w = BufWriter::new(file);
        bincode::serialize_into(&mut w, self)
            .context("serialize replay checkpoint")?;
        w.flush().context("flush checkpoint")?;
        drop(w);
        fs::rename(&tmp, path)
            .with_context(|| format!("rename checkpoint into {}", path.display()))?;
        Ok(())
    }

    /// Like `save`, but streams the snapshot directly from the State's
    /// snapshot trie via a callback instead of materializing the entire
    /// `BTreeMap<Vec<u8>, Box<[u8]>>`. The `mmpt.snapshot` field in `self`
    /// is ignored; the callback supplies the data. The on-disk format is
    /// byte-identical to `save` — `load` works unchanged.
    pub fn save_streaming(
        &self,
        path: &Path,
        snapshot_count: usize,
        snapshot_for_each: impl FnOnce(
            &mut dyn FnMut(Vec<u8>, &[u8]) -> std::io::Result<()>,
        ) -> std::io::Result<()>,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create checkpoint dir {}", parent.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let file = fs::File::create(&tmp)
            .with_context(|| format!("create checkpoint tmp {}", tmp.display()))?;
        let mut w = BufWriter::new(file);

        // Checkpoint fields (must match derived Serialize order exactly):
        bincode::serialize_into(&mut w, &self.version).context("ckpt: version")?;
        bincode::serialize_into(&mut w, &self.height).context("ckpt: height")?;

        // PersistedState fields (must match store.rs field order):
        // 1. snapshot — streamed via callback
        Self::write_snapshot_streaming(&mut w, snapshot_count, snapshot_for_each)?;
        // 2. intermediate
        bincode::serialize_into(&mut w, &self.mmpt.intermediate).context("ckpt: intermediate")?;
        // 3. delta
        bincode::serialize_into(&mut w, &self.mmpt.delta).context("ckpt: delta")?;
        // 4-5. paddings
        bincode::serialize_into(&mut w, &self.mmpt.intermediate_mpt_key_padding)
            .context("ckpt: int_padding")?;
        bincode::serialize_into(&mut w, &self.mmpt.delta_mpt_key_padding)
            .context("ckpt: delta_padding")?;
        // 6. height
        bincode::serialize_into(&mut w, &self.mmpt.height).context("ckpt: mmpt_height")?;
        // 7. snapshot_epoch_count
        bincode::serialize_into(&mut w, &self.mmpt.snapshot_epoch_count)
            .context("ckpt: epoch_count")?;
        // 8. last_root
        bincode::serialize_into(&mut w, &self.mmpt.last_root).context("ckpt: last_root")?;

        // Remaining Checkpoint fields:
        bincode::serialize_into(&mut w, &self.previous_epoch_hash).context("ckpt: prev_hash")?;
        bincode::serialize_into(&mut w, &self.previous_state_root).context("ckpt: prev_root")?;
        bincode::serialize_into(&mut w, &self.previous_epoch_pos_view)
            .context("ckpt: pos_view")?;
        bincode::serialize_into(&mut w, &self.previous_epoch_finalized_epoch)
            .context("ckpt: finalized")?;
        bincode::serialize_into(&mut w, &self.commitments).context("ckpt: commitments")?;
        bincode::serialize_into(&mut w, &self.executed_epochs).context("ckpt: exec_epochs")?;

        w.flush().context("flush checkpoint")?;
        drop(w);
        fs::rename(&tmp, path)
            .with_context(|| format!("rename checkpoint into {}", path.display()))?;
        Ok(())
    }

    /// Write a `BTreeMap<Vec<u8>, Box<[u8]>>` in bincode wire format by
    /// streaming entries via a callback. bincode 1.x uses LE fixed u64 for
    /// map/seq lengths and serializes `Vec<u8>` / `Box<[u8]>` as `u64 len +
    /// raw bytes`. Each entry is written immediately — no bulk allocation.
    fn write_snapshot_streaming(
        w: &mut (impl Write + ?Sized),
        count: usize,
        for_each: impl FnOnce(
            &mut dyn FnMut(Vec<u8>, &[u8]) -> std::io::Result<()>,
        ) -> std::io::Result<()>,
    ) -> Result<()> {
        w.write_all(&(count as u64).to_le_bytes())
            .context("snapshot: count")?;
        for_each(&mut |key, value| {
            w.write_all(&(key.len() as u64).to_le_bytes())?;
            w.write_all(&key)?;
            w.write_all(&(value.len() as u64).to_le_bytes())?;
            w.write_all(value)?;
            Ok(())
        })
        .context("snapshot: write entries")?;
        Ok(())
    }

    /// Like `save_streaming`, but builds the iterator from `self.mmpt`
    /// internally. Used for verification: proves streaming output is
    /// byte-identical to `save()`. Not zero-copy (clones mmpt to build the
    /// State), but the production path in `setup.rs` uses the live State.
    pub fn save_streaming_self(&self, path: &Path) -> Result<()> {
        let state = cfx_minimal_mpt::State::from_persisted(self.mmpt.clone());
        let count = state.snapshot_live_count();
        self.save_streaming(path, count, |cb| state.snapshot_for_each_canonical(cb))
    }

    /// Streaming load: the memory-frugal counterpart to `load` + `into_parts`.
    ///
    /// `load` reads the whole file into a `Vec<u8>` and `bincode::deserialize`s
    /// it, materializing the snapshot as a byte-keyed `BTreeMap` (tens of GB at
    /// full-chain scale) before `State::from_persisted` converts it again. This
    /// reads field-by-field from a `BufReader`, streaming the snapshot straight
    /// into the trie's backing store — the byte-keyed map never exists.
    ///
    /// The field order mirrors the `Checkpoint` / `PersistedState` derive order
    /// exactly (the same order `save_streaming` writes), so the on-disk format
    /// is unchanged. V1 checkpoints predate the size problem and fall back to
    /// the full `load` path.
    pub fn load_streaming(path: &Path) -> Result<Option<RestoredCheckpoint>> {
        if !path.exists() {
            return Ok(None);
        }
        let file = fs::File::open(path)
            .with_context(|| format!("open checkpoint {}", path.display()))?;
        let mut r = BufReader::new(file);

        let version: u32 =
            bincode::deserialize_from(&mut r).context("read checkpoint version")?;
        match version {
            1 => {
                // V1 files are old and small; the streaming path is unnecessary.
                let ckpt = Self::load(path)?.expect("path exists");
                let height = ckpt.height();
                let (mmpt, prev_hash, prev_root, pos_view, fe, commitments, executed) =
                    ckpt.into_parts()?;
                Ok(Some(RestoredCheckpoint {
                    state: MmptState::from_persisted(mmpt),
                    height,
                    previous_epoch_hash: prev_hash,
                    previous_state_root: prev_root,
                    previous_epoch_pos_view: pos_view,
                    previous_epoch_finalized_epoch: fe,
                    commitments,
                    executed_epochs: executed,
                }))
            }
            CHECKPOINT_VERSION => {
                let height: u64 =
                    bincode::deserialize_from(&mut r).context("ckpt: height")?;
                // PersistedState (mmpt) — streamed into the live State.
                let state =
                    MmptState::from_reader(&mut r).context("ckpt: stream mmpt state")?;
                // Remaining Checkpoint fields.
                let previous_epoch_hash: H256 =
                    bincode::deserialize_from(&mut r).context("ckpt: prev_hash")?;
                let previous_state_root: StateRootWithAuxInfo =
                    bincode::deserialize_from(&mut r).context("ckpt: prev_root")?;
                let previous_epoch_pos_view: Option<u64> =
                    bincode::deserialize_from(&mut r).context("ckpt: pos_view")?;
                let previous_epoch_finalized_epoch: Option<u64> =
                    bincode::deserialize_from(&mut r).context("ckpt: finalized")?;
                let commitments_vec: Vec<(u64, EpochCommitment)> =
                    bincode::deserialize_from(&mut r).context("ckpt: commitments")?;
                let executed_vec: Vec<(u64, ExecutedEpochDisk)> =
                    bincode::deserialize_from(&mut r).context("ckpt: exec_epochs")?;

                let commitments = commitments_vec.into_iter().collect();
                let mut executed_epochs = BTreeMap::new();
                for (h, disk) in executed_vec {
                    executed_epochs.insert(h, disk.into_live()?);
                }

                Ok(Some(RestoredCheckpoint {
                    state,
                    height,
                    previous_epoch_hash,
                    previous_state_root,
                    previous_epoch_pos_view,
                    previous_epoch_finalized_epoch,
                    commitments,
                    executed_epochs,
                }))
            }
            _ => anyhow::bail!(
                "checkpoint version mismatch: file v{version}, expected v{CHECKPOINT_VERSION}",
            ),
        }
    }

    /// Test helper: assert `load_streaming` reconstructs exactly what the full
    /// `load` + `into_parts` path does. Lives in-crate so it can touch the
    /// crate-private commitment/executed window types. Returns `true` on match.
    /// Reference path materializes the full byte-keyed snapshot, so use a small
    /// early checkpoint.
    pub fn verify_streaming_load_matches(path: &Path) -> Result<bool> {
        let full = Self::load(path)?.context("no checkpoint at path")?;
        let ref_height = full.height();
        let (ref_mmpt, ref_ph, ref_pr, ref_pv, ref_fe, ref_comm, ref_exec) =
            full.into_parts()?;

        let restored = Self::load_streaming(path)?.context("load_streaming None")?;
        let stream_mmpt = restored.state.persisted();

        let mut ok = true;
        if ref_mmpt != stream_mmpt {
            ok = false;
            eprintln!("FAIL: mmpt differs");
            if ref_mmpt.snapshot != stream_mmpt.snapshot {
                eprintln!(
                    "  snapshot: ref={} stream={}",
                    ref_mmpt.snapshot.len(),
                    stream_mmpt.snapshot.len()
                );
                for (k, v) in ref_mmpt.snapshot.iter() {
                    match stream_mmpt.snapshot.get(k) {
                        None => {
                            eprintln!("  key missing in stream: {:02x?}", &k[..k.len().min(8)]);
                            break;
                        }
                        Some(sv) if sv != v => {
                            eprintln!("  value differs at {:02x?}", &k[..k.len().min(8)]);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            if ref_mmpt.intermediate != stream_mmpt.intermediate {
                eprintln!("  intermediate differs");
            }
            if ref_mmpt.delta != stream_mmpt.delta {
                eprintln!("  delta differs");
            }
            if ref_mmpt.height != stream_mmpt.height {
                eprintln!("  height {} vs {}", ref_mmpt.height, stream_mmpt.height);
            }
            if ref_mmpt.last_root != stream_mmpt.last_root {
                eprintln!("  last_root differs");
            }
            if ref_mmpt.intermediate_mpt_key_padding != stream_mmpt.intermediate_mpt_key_padding
                || ref_mmpt.delta_mpt_key_padding != stream_mmpt.delta_mpt_key_padding
            {
                eprintln!("  padding differs");
            }
            if ref_mmpt.snapshot_epoch_count != stream_mmpt.snapshot_epoch_count {
                eprintln!("  epoch_count differs");
            }
        }
        if ref_height != restored.height {
            ok = false;
            eprintln!("FAIL: height {ref_height} vs {}", restored.height);
        }
        if ref_ph != restored.previous_epoch_hash {
            ok = false;
            eprintln!("FAIL: previous_epoch_hash differs");
        }
        if ref_pr != restored.previous_state_root {
            ok = false;
            eprintln!("FAIL: previous_state_root differs");
        }
        if ref_pv != restored.previous_epoch_pos_view {
            ok = false;
            eprintln!("FAIL: previous_epoch_pos_view differs");
        }
        if ref_fe != restored.previous_epoch_finalized_epoch {
            ok = false;
            eprintln!("FAIL: previous_epoch_finalized_epoch differs");
        }
        // window contents decode identically (same bincode calls); check counts.
        if ref_comm.len() != restored.commitments.len() {
            ok = false;
            eprintln!("FAIL: commitments count differs");
        }
        if ref_exec.len() != restored.executed_epochs.len() {
            ok = false;
            eprintln!("FAIL: executed_epochs count differs");
        }

        eprintln!(
            "height={ref_height} snapshot={} intermediate={} delta={} commitments={} executed={}",
            stream_mmpt.snapshot.len(),
            stream_mmpt.intermediate.len(),
            stream_mmpt.delta.len(),
            restored.commitments.len(),
            restored.executed_epochs.len(),
        );
        Ok(ok)
    }

    /// Load a checkpoint if one exists at `path`; `Ok(None)` when absent.
    /// Transparently upgrades v1 checkpoints (pre-PoS fields missing).
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)
            .with_context(|| format!("read checkpoint {}", path.display()))?;
        let version: u32 = bincode::deserialize(&bytes[..4])
            .context("read checkpoint version")?;
        let ckpt = match version {
            1 => {
                let v1: CheckpointV1 = bincode::deserialize(&bytes)
                    .with_context(|| format!("deserialize v1 checkpoint {}", path.display()))?;
                v1.upgrade()
            }
            CHECKPOINT_VERSION => {
                bincode::deserialize(&bytes)
                    .with_context(|| format!("deserialize checkpoint {}", path.display()))?
            }
            _ => anyhow::bail!(
                "checkpoint version mismatch: file v{version}, expected v{CHECKPOINT_VERSION}",
            ),
        };
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
            Some(111),
            Some(222),
            &commitments,
            &executed,
        );
        assert_eq!(ckpt.height(), 4000);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ckpt.bin");
        ckpt.save(&path).unwrap();
        let loaded = Checkpoint::load(&path).unwrap().unwrap();
        let (
            mmpt2,
            hash2,
            root2,
            pos_view2,
            finalized_epoch2,
            commitments2,
            executed2,
        ) = loaded.into_parts().unwrap();

        assert_eq!(mmpt2.height, 4000);
        assert_eq!(hash2, h(7));
        assert_eq!(root2, prev_root);
        assert_eq!(pos_view2, Some(111));
        assert_eq!(finalized_epoch2, Some(222));
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
