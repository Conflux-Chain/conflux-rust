use super::{
    Checkpoint, CheckpointV1, ExecutedEpochDisk, RestoredCheckpoint,
    CHECKPOINT_VERSION,
};
use crate::consensus::EpochCommitment;
use anyhow::{Context, Result};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_minimal_mpt::State as MmptState;
use cfx_types::H256;
use std::{collections::BTreeMap, fs, io::BufReader, path::Path};

impl Checkpoint {
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

        let version: u32 = bincode::deserialize_from(&mut r)
            .context("read checkpoint version")?;
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

    /// Load a checkpoint if one exists at `path`; `Ok(None)` when absent.
    /// Transparently upgrades v1 checkpoints (pre-PoS fields missing).
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)
            .with_context(|| format!("read checkpoint {}", path.display()))?;
        if bytes.len() < 4 {
            anyhow::bail!("checkpoint file too short");
        }
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
