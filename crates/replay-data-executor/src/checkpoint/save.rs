use super::{Checkpoint, ExecutedEpochDisk, CHECKPOINT_VERSION};
use crate::consensus::{EpochCommitment, ExecutedEpoch};
use anyhow::{Context, Result};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_minimal_mpt::State as MmptState;
use cfx_types::H256;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufWriter, Write},
    path::Path,
};

/// Borrowed view over the data needed to write a streaming checkpoint.
/// Save-side counterpart to `RestoredCheckpoint` (load output, owns data).
pub(crate) struct CheckpointParts<'a> {
    pub state: &'a MmptState,
    pub previous_epoch_hash: H256,
    pub previous_state_root: &'a StateRootWithAuxInfo,
    pub previous_epoch_pos_view: Option<u64>,
    pub previous_epoch_finalized_epoch: Option<u64>,
    pub commitments: &'a BTreeMap<u64, EpochCommitment>,
    pub executed_epochs: &'a BTreeMap<u64, ExecutedEpoch>,
}

impl CheckpointParts<'_> {
    /// Atomically write the checkpoint while delegating the MMPT body encoding
    /// to `cfx-minimal-mpt`.
    pub fn save_streaming(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create checkpoint dir {}", parent.display())
            })?;
        }
        let tmp = path.with_extension("tmp");
        let file = fs::File::create(&tmp).with_context(|| {
            format!("create checkpoint tmp {}", tmp.display())
        })?;
        let mut w = BufWriter::new(file);

        bincode::serialize_into(&mut w, &CHECKPOINT_VERSION)
            .context("ckpt: version")?;
        bincode::serialize_into(&mut w, &self.state.height())
            .context("ckpt: height")?;

        self.state
            .write_streaming(&mut w)
            .context("ckpt: stream mmpt state")?;

        bincode::serialize_into(&mut w, &self.previous_epoch_hash)
            .context("ckpt: prev_hash")?;
        bincode::serialize_into(&mut w, self.previous_state_root)
            .context("ckpt: prev_root")?;
        bincode::serialize_into(&mut w, &self.previous_epoch_pos_view)
            .context("ckpt: pos_view")?;
        bincode::serialize_into(&mut w, &self.previous_epoch_finalized_epoch)
            .context("ckpt: finalized")?;

        let commitments: Vec<(u64, EpochCommitment)> =
            self.commitments.iter().map(|(h, c)| (*h, *c)).collect();
        let executed_epochs: Vec<(u64, ExecutedEpochDisk)> = self
            .executed_epochs
            .iter()
            .map(|(h, d)| (*h, ExecutedEpochDisk::from_live(d)))
            .collect();

        bincode::serialize_into(&mut w, &commitments)
            .context("ckpt: commitments")?;
        bincode::serialize_into(&mut w, &executed_epochs)
            .context("ckpt: exec_epochs")?;

        w.flush().context("flush checkpoint")?;
        drop(w);
        fs::rename(&tmp, path).with_context(|| {
            format!("rename checkpoint into {}", path.display())
        })?;
        Ok(())
    }
}

impl Checkpoint {
    /// Atomically write the checkpoint (tmp + rename, like minimal-mpt's
    /// `FileStore`), so a crash mid-write never leaves a torn file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create checkpoint dir {}", parent.display())
            })?;
        }
        let tmp = path.with_extension("tmp");
        let file = fs::File::create(&tmp).with_context(|| {
            format!("create checkpoint tmp {}", tmp.display())
        })?;
        let mut w = BufWriter::new(file);
        bincode::serialize_into(&mut w, self)
            .context("serialize replay checkpoint")?;
        w.flush().context("flush checkpoint")?;
        drop(w);
        fs::rename(&tmp, path).with_context(|| {
            format!("rename checkpoint into {}", path.display())
        })?;
        Ok(())
    }

    /// Like `save_streaming`, but builds the iterator from `self.mmpt`
    /// internally. Used for verification: proves streaming output is
    /// byte-identical to `save()`. Not zero-copy (clones mmpt to build the
    /// State), but the production path in `setup.rs` uses the live State.
    pub fn save_streaming_self(&self, path: &Path) -> Result<()> {
        let state = cfx_minimal_mpt::State::from_persisted(self.mmpt.clone());
        let commitments: BTreeMap<u64, EpochCommitment> =
            self.commitments.iter().map(|(h, c)| (*h, *c)).collect();
        let mut executed_epochs = BTreeMap::new();
        for (h, disk) in &self.executed_epochs {
            executed_epochs.insert(*h, disk.clone().into_live()?);
        }
        CheckpointParts {
            state: &state,
            previous_epoch_hash: self.previous_epoch_hash,
            previous_state_root: &self.previous_state_root,
            previous_epoch_pos_view: self.previous_epoch_pos_view,
            previous_epoch_finalized_epoch: self.previous_epoch_finalized_epoch,
            commitments: &commitments,
            executed_epochs: &executed_epochs,
        }
        .save_streaming(path)
    }
}
