use super::Checkpoint;
use anyhow::{Context, Result};
use std::{
    fs,
    io::{BufWriter, Write},
    path::Path,
};

impl Checkpoint {
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
}
