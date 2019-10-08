// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::state::storage::{Chunk, ChunkKey};
use keccak_hash::keccak;
use parking_lot::RwLock;
use primitives::StateRoot;
use rlp::{Encodable, Rlp};
use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    thread,
};

#[derive(Debug)]
struct ChunkMetadata {
    key: ChunkKey,
    file: PathBuf,
}

#[derive(Default)]
struct State {
    pending: VecDeque<ChunkMetadata>,
    restoring: Option<ChunkMetadata>,
    restored: Vec<ChunkMetadata>,
}

impl State {
    fn next(&mut self) -> Option<&ChunkMetadata> {
        if let Some(chunk) = self.restoring.take() {
            self.restored.push(chunk);
        }

        let chunk = self.pending.pop_front()?;
        self.restoring = Some(chunk);

        self.restoring.as_ref()
    }
}

#[derive(Default)]
pub struct Restorer {
    state: Arc<RwLock<State>>,
    progress: Arc<RestoreProgress>,
    dir: String,
}

impl Restorer {
    /// Append a chunk for restoration.
    pub fn append(&self, key: ChunkKey, chunk: Chunk) {
        let file = match self.write_chunk_to_file(&key, chunk) {
            Some(file) => file,
            None => return,
        };

        self.progress.total.fetch_add(1, Relaxed);

        let mut state = self.state.write();
        state.pending.push_back(ChunkMetadata { key, file });
    }

    fn write_chunk_to_file(
        &self, key: &ChunkKey, chunk: Chunk,
    ) -> Option<PathBuf> {
        if let Err(e) = fs::create_dir_all(&self.dir) {
            panic!("failed to create directory to store snapshot chunks: directory = {:?}, error = {:?}", self.dir, e);
        }

        let contents = chunk.rlp_bytes();
        let hash = keccak(contents.as_slice());
        let filename = format!("chunk_{:?}", hash);
        let mut file = PathBuf::from(&self.dir);
        file.push(&filename);

        if file.exists() {
            warn!("snapshot chunk already exists, key = {:?}", key);
            return None;
        }

        if let Err(e) = fs::write(&file, contents.as_slice()) {
            panic!("failed to store snapshot chunk for restoration: file = {:?}, error = {:?}", file, e);
        }

        Some(file)
    }

    /// Start to restore chunks asynchronously.
    pub fn start_to_restore(&self) {
        let state_cloned = self.state.clone();
        let progress_cloned = self.progress.clone();

        thread::Builder::new()
            .name("SyncCheckpoint".into())
            .spawn(move || {
                let total = progress_cloned.total.load(Relaxed);
                debug!("start to restore snapshot chunks, total = {}", total);

                while let Some(metadata) = state_cloned.write().next() {
                    let _chunk = Self::read_chunk_from_file(&metadata.file);

                    // todo use storage API to restore the chunk

                    progress_cloned.completed.fetch_add(1, Relaxed);
                }

                debug!(
                    "complete to restore snapshot chunks, total = {}",
                    total
                );
            })
            .expect("failed to create thread to synchronize checkpoint state");
    }

    fn read_chunk_from_file(file: &PathBuf) -> Chunk {
        let contents = match fs::read(file) {
            Ok(contents) => contents,
            Err(e) => {
                panic!("failed to read snapshot chunk for restoration: file = {:?}, error = {:?}", file, e);
            }
        };

        match Rlp::new(&contents).as_val::<Chunk>() {
            Ok(val) => val,
            Err(e) => {
                panic!("failed to restore snapshot chunk due to decode error: file = {:?}, error = {:?}", file, e);
            }
        }
    }

    pub fn progress(&self) -> &RestoreProgress { self.progress.as_ref() }

    pub fn restored_state_root(&self) -> StateRoot { unimplemented!() }

    // todo delete all the temp snapshot chunk files after restoration succeeded
    // todo cleanup and start to sync new checkpoint
}

#[derive(Default, Debug)]
pub struct RestoreProgress {
    total: AtomicUsize,
    completed: AtomicUsize,
}

impl RestoreProgress {
    pub fn is_completed(&self) -> bool {
        let total = self.total.load(Relaxed);
        let completed = self.completed.load(Relaxed);
        completed >= total
    }
}
