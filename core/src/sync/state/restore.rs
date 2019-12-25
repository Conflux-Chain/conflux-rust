// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    storage::{
        state_manager::StateManager,
        storage_db::{SnapshotDbManagerTrait, SnapshotInfo},
        FullSyncVerifier,
    },
    sync::state::storage::{Chunk, ChunkKey, ChunkReader, RangedManifest},
    BlockDataManager,
};
use cfx_types::H256;
use parking_lot::RwLock;
use primitives::{EpochId, MerkleHash, NULL_EPOCH};
use rlp::Rlp;
use std::{
    collections::{HashMap, VecDeque},
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
    snapshot_epoch_id: EpochId,
    pub snapshot_merkle_root: MerkleHash,
    pub manifest: Option<RangedManifest>,
}

impl Default for Restorer {
    fn default() -> Self { Self::new_with_default_root_dir(H256::zero(), None) }
}

impl Restorer {
    pub fn new_with_default_root_dir(
        checkpoint: H256, manifest: Option<RangedManifest>,
    ) -> Self {
        let root_dir = current_dir()
            .unwrap_or(PathBuf::from("./"))
            .join("state_checkpoints_restoration")
            .to_str()
            .expect("state chunk restoration directory should not be empty")
            .to_string();

        Self::new(root_dir, checkpoint, manifest)
    }

    pub fn new(
        root_dir: String, checkpoint: H256, manifest: Option<RangedManifest>,
    ) -> Self {
        Restorer {
            state: Default::default(),
            progress: Default::default(),
            dir: Chunk::epoch_dir(root_dir, &checkpoint),
            snapshot_epoch_id: checkpoint,
            snapshot_merkle_root: Default::default(),
            manifest,
        }
    }

    /// Append a chunk for restoration.
    pub fn append(&self, key: ChunkKey, chunk: Chunk) {
        chunk
            .dump(self.dir.as_path(), &key)
            .expect("failed to dump chunk to file");

        self.progress.total.fetch_add(1, Relaxed);

        let mut state = self.state.write();
        state.pending.push_back(key);
    }

    /// Start to restore chunks asynchronously.
    pub fn start_to_restore(
        &self, state_manager: Arc<StateManager>, data_man: &BlockDataManager,
    ) {
        let state_cloned = self.state.clone();
        let progress_cloned = self.progress.clone();
        let chunk_reader = ChunkReader::new_with_epoch_dir(self.dir.clone())
            .expect("cannot find the chunk store for restoration");
        let snapshot_epoch_id = self.snapshot_epoch_id.clone();
        let snapshot_merkle_root = self.snapshot_merkle_root;
        let height = data_man
            .block_header_by_hash(&snapshot_epoch_id)
            .expect("state being synced should have block header")
            .height();
        let manifest = self.manifest.clone().expect("manifest already set");

        thread::Builder::new()
            .name("SyncCheckpoint".into())
            .spawn(move || {
                let total = progress_cloned.total.load(Relaxed);
                debug!("start to restore snapshot chunks, total = {}", total);
                let mut chunk_key_to_index = HashMap::new();
                let mut chunk_boundaries = Vec::new();
                let mut chunk_boundary_proof = Vec::new();
                for (i, chunk_key) in manifest.chunks.iter().enumerate() {
                    chunk_key_to_index.insert(chunk_key.key.clone(), i);
                    if let Some(boundary) = &chunk_key.key.upper_bound_excl {
                        chunk_boundaries.push(boundary.clone());
                        chunk_boundary_proof.push(chunk_key.proof.clone())
                    }
                }
                assert_eq!(
                    chunk_boundary_proof.len() + 1,
                    manifest.chunks.len()
                );
                let snapshot_db_manager = state_manager
                    .get_storage_manager()
                    .get_snapshot_manager()
                    .get_snapshot_db_manager();
                let mut verifier = FullSyncVerifier::new(
                    manifest.chunks.len(),
                    chunk_boundaries,
                    chunk_boundary_proof,
                    snapshot_merkle_root,
                    snapshot_db_manager,
                    &snapshot_epoch_id,
                )
                .unwrap();

                while let Some(key) = state_cloned.write().next() {
                    let index = chunk_key_to_index.get(key).unwrap();
                    let chunk = chunk_reader
                        .chunk_raw(key)
                        .expect("failed to read chunk from restoration store")
                        .expect("cannot find chunk for restoration");
                    let chunk = Rlp::new(&chunk)
                        .as_val::<Chunk>()
                        .expect("failed to decode chunk for restoration");
                    let mut keys = Vec::new();
                    let mut values = Vec::new();
                    for item in chunk.items {
                        let key = item.key;
                        let value = item.value;
                        keys.push(key);
                        values.push(value.into_boxed_slice());
                    }
                    verifier
                        .restore_chunk(*index, &keys, values)
                        .expect("success");
                    progress_cloned.completed.fetch_add(1, Relaxed);
                }
                snapshot_db_manager
                    .finalize_full_sync_snapshot(
                        &snapshot_epoch_id,
                        &snapshot_merkle_root,
                    )
                    .expect("finalize");
                let snapshot_info = SnapshotInfo {
                    serve_one_step_sync: false,
                    merkle_root: snapshot_merkle_root,
                    // We will not sync true genesis, so height should not be 0
                    parent_snapshot_height: height
                        - state_manager
                            .get_storage_manager()
                            .get_snapshot_epoch_count(),
                    height,
                    // Set intermediate_mpt to None
                    parent_snapshot_epoch_id: NULL_EPOCH,
                    pivot_chain_parts: vec![snapshot_epoch_id],
                };
                state_manager
                    .get_storage_manager()
                    .register_new_snapshot(snapshot_info, true);

                debug!(
                    "complete to restore snapshot chunks, total = {}",
                    total
                );
            })
            .expect("failed to create thread to synchronize checkpoint state");
    }

    pub fn progress(&self) -> &RestoreProgress { self.progress.as_ref() }

    pub fn restored_state_root(
        &self, _state_manager: Arc<StateManager>,
    ) -> MerkleHash {
        // TODO Double check the restored snapshot merkle root
        // But if all chunks pass the verification, it should be the same as
        // the this snapshot_merkle_root
        self.snapshot_merkle_root
    }
}

impl Drop for Restorer {
    fn drop(&mut self) {
        if !self.snapshot_epoch_id.is_zero() {
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
