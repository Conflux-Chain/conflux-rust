// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        state::StateTrait,
        state_manager::{StateManager, StateManagerTrait},
        SnapshotAndEpochIdRef,
    },
    sync::state::delta::{Chunk, ChunkKey, ChunkReader, StateDumper},
};
use cfx_types::H256;
use parking_lot::RwLock;
use primitives::StateRoot;
use rlp::Rlp;
use std::{
    collections::VecDeque,
    env::current_dir,
    fs::remove_dir_all,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    thread,
};

#[derive(Default)]
struct State {
    pending: VecDeque<ChunkKey>,
    restoring: Option<ChunkKey>,
    restored: Vec<ChunkKey>,
}

impl State {
    fn next(&mut self) -> Option<&ChunkKey> {
        if let Some(chunk) = self.restoring.take() {
            self.restored.push(chunk);
        }

        let chunk = self.pending.pop_front()?;
        self.restoring = Some(chunk);

        self.restoring.as_ref()
    }
}

pub struct Restorer {
    state: Arc<RwLock<State>>,
    progress: Arc<RestoreProgress>,
    dir: PathBuf,
    checkpoint: H256,
}

impl Default for Restorer {
    fn default() -> Self { Self::new_with_default_root_dir(H256::zero()) }
}

impl Restorer {
    pub fn new_with_default_root_dir(checkpoint: H256) -> Self {
        let root_dir = current_dir()
            .unwrap_or(PathBuf::from("./"))
            .join("state_checkpoints_restoration")
            .to_str()
            .expect("state chunk restoration directory should not be empty")
            .to_string();

        Self::new(root_dir, checkpoint)
    }

    pub fn new(root_dir: String, checkpoint: H256) -> Self {
        Restorer {
            state: Default::default(),
            progress: Default::default(),
            dir: StateDumper::epoch_dir(root_dir, &checkpoint),
            checkpoint,
        }
    }

    /// Append a chunk for restoration.
    pub fn append(&self, key: ChunkKey, chunk: Chunk) {
        chunk
            .dump(self.dir.as_path())
            .expect("failed to dump chunk to file");

        self.progress.total.fetch_add(1, Relaxed);

        let mut state = self.state.write();
        state.pending.push_back(key);
    }

    /// Start to restore chunks asynchronously.
    pub fn start_to_restore(&self, state_manager: Arc<StateManager>) {
        let state_cloned = self.state.clone();
        let progress_cloned = self.progress.clone();
        let chunk_reader = ChunkReader::new_with_epoch_dir(self.dir.clone())
            .expect("cannot find the chunk store for restoration");
        let checkpoint = self.checkpoint.clone();

        thread::Builder::new()
            .name("SyncCheckpoint".into())
            .spawn(move || {
                let total = progress_cloned.total.load(Relaxed);
                debug!("start to restore snapshot chunks, total = {}", total);

                while let Some(key) = state_cloned.write().next() {
                    let chunk = chunk_reader
                        .chunk_raw(key)
                        .expect("failed to read chunk from restoration store")
                        .expect("cannot find chunk for restoration");
                    let chunk = Rlp::new(&chunk)
                        .as_val::<Chunk>()
                        .expect("failed to decode chunk for restoration");

                    let epoch_id =
                        SnapshotAndEpochIdRef::new(&checkpoint, None);
                    let mut state = state_manager
                        .get_state_no_commit(epoch_id)
                        .expect("failed to get checkpoint state")
                        .unwrap_or_else(|| {
                            state_manager.get_state_for_genesis_write()
                        });

                    chunk
                        .restore(&mut state, Some(checkpoint))
                        .expect("failed to restore chunk");

                    progress_cloned.completed.fetch_add(1, Relaxed);
                }

                debug!(
                    "complete to restore snapshot chunks, total = {}",
                    total
                );
            })
            .expect("failed to create thread to synchronize checkpoint state");
    }

    pub fn progress(&self) -> &RestoreProgress { self.progress.as_ref() }

    pub fn restored_state_root(
        &self, state_manager: Arc<StateManager>,
    ) -> StateRoot {
        let epoch_id = SnapshotAndEpochIdRef::new(&self.checkpoint, None);
        let state = state_manager
            .get_state_no_commit(epoch_id)
            .expect("failed to get checkpoint state")
            .expect("cannot find the checkpoint state");
        state
            .get_state_root()
            .expect("failed to get state root")
            .expect("restored checkpoint state root not found")
            .state_root
    }
}

impl Drop for Restorer {
    fn drop(&mut self) {
        if !self.checkpoint.is_zero() {
            if let Err(e) = remove_dir_all(&self.dir) {
                error!("failed to cleanup checkpoint chunk store: {:?}", e);
            }
        }
    }
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
