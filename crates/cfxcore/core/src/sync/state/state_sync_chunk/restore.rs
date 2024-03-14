// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::state::storage::{Chunk, ChunkKey};
use cfx_storage::{
    state_manager::StateManager,
    storage_db::{SnapshotDbManagerTrait, SnapshotInfo},
    FullSyncVerifier, Result as StorageResult, SnapshotDbManagerSqlite,
};
use primitives::{EpochId, MerkleHash, NULL_EPOCH};
use std::sync::Arc;

pub struct Restorer {
    pub snapshot_epoch_id: EpochId,
    pub snapshot_merkle_root: MerkleHash,

    /// The verifier for chunks.
    /// Initialized after receiving a valid manifest.
    verifier: Option<FullSyncVerifier<SnapshotDbManagerSqlite>>,
}

impl Restorer {
    pub fn new(
        snapshot_epoch_id: EpochId, snapshot_merkle_root: MerkleHash,
    ) -> Self {
        Restorer {
            snapshot_epoch_id,
            snapshot_merkle_root,
            verifier: None,
        }
    }

    pub fn initialize_verifier(
        &mut self, verifier: FullSyncVerifier<SnapshotDbManagerSqlite>,
    ) {
        self.verifier = Some(verifier);
    }

    /// Append a chunk for restoration.
    pub fn append(&mut self, key: ChunkKey, chunk: Chunk) -> bool {
        match &mut self.verifier {
            // Not waiting for chunks
            None => false,
            Some(verifier) => {
                match verifier.restore_chunk(
                    &key.upper_bound_excl,
                    &chunk.keys,
                    chunk.values,
                ) {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(e) => {
                        warn!("error for restore_chunk: err={:?}", e);
                        false
                    }
                }
            }
        }
    }

    /// Start to restore chunks asynchronously.
    pub fn finalize_restoration(
        &mut self, state_manager: Arc<StateManager>,
        snapshot_info: SnapshotInfo,
        parent_snapshot_info: Option<SnapshotInfo>,
        intermediate_trie_root_merkle: MerkleHash,
    ) -> StorageResult<()> {
        // Release temp snapshot db so it can be renamed on Windows.
        // `self.verifier()` is never unwrapped, so it's safe to set it to None,
        self.verifier = None;

        let storage_manager = state_manager.get_storage_manager_arc();

        let parent_snapshot = if let Some(snapshot_info) =
            parent_snapshot_info.clone()
        {
            let snapshot_epoch_id = snapshot_info.get_snapshot_epoch_id();
            if let Some(snapshot_info_in_db) =
                storage_manager.get_snapshot_info_at_epoch(snapshot_epoch_id)
            {
                if snapshot_info.merkle_root != snapshot_info_in_db.merkle_root
                    || snapshot_info.get_snapshot_epoch_id()
                        != snapshot_info_in_db.get_snapshot_epoch_id()
                {
                    debug!("destory snapshot {:?}", snapshot_epoch_id);
                    storage_manager
                        .get_snapshot_manager()
                        .get_snapshot_db_manager()
                        .destroy_snapshot(snapshot_epoch_id)?;
                    Some(snapshot_info)
                } else {
                    None
                }
            } else {
                Some(snapshot_info)
            }
        } else {
            None
        };

        let mut snapshot_info_map_locked = storage_manager
            .get_snapshot_manager()
            .get_snapshot_db_manager()
            .finalize_full_sync_snapshot(
                &self.snapshot_epoch_id,
                &self.snapshot_merkle_root,
                &storage_manager.snapshot_info_map_by_epoch,
            )?;

        if let Some(parent_snapshot) = parent_snapshot {
            storage_manager.register_new_snapshot(
                parent_snapshot,
                &mut snapshot_info_map_locked,
            )?;
        }

        let snapshot_height = snapshot_info.height;
        storage_manager.register_new_snapshot(
            snapshot_info,
            &mut snapshot_info_map_locked,
        )?;

        debug!(
            "intermediate_trie_root_merkle for next epoch in finalize_restoration {:?}",
            intermediate_trie_root_merkle
        );
        *storage_manager.intermediate_trie_root_merkle.write() =
            Some(intermediate_trie_root_merkle);

        // rewrite for special case
        *storage_manager.persist_state_from_initialization.write() = Some((
            None,
            std::collections::HashSet::from([NULL_EPOCH]),
            snapshot_height,
            None,
        ));

        debug!("Completed snapshot restoration.");
        Ok(())
    }
}
