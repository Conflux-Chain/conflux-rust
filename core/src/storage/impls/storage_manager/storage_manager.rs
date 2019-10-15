// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: correctly order code blocks.
pub struct StorageManager {
    delta_db_manager: DeltaDbManager,
    snapshot_manager: Box<
        dyn SnapshotManagerTrait<
                SnapshotDb = SnapshotDb,
                SnapshotDbManager = SnapshotDbManager,
            > + Send
            + Sync,
    >,
    maybe_db_errors: MaybeDbErrors,
    // FIXME: when do insertions happen?
    snapshot_associated_mpts:
        RwLock<HashMap<MerkleHash, (Arc<DeltaMpt>, Arc<DeltaMpt>)>>,

    in_progress_snapshoting_tasks:
        RwLock<HashMap<EpochId, InProgressSnapshotInfo>>,
    // FIXME: persistent in db.
    // The order doesn't matter as long as parent snapshot comes before
    // children snapshots.
    // Note that for archive node the list here is just a subset of what's
    // available.
    current_snapshots: RwLock<Vec<SnapshotInfo>>,
}

// FIXME: the thread variable is used. But it's subject to refinements for sure.
#[allow(dead_code)]
struct InProgressSnapshotInfo {
    snapshot_info: SnapshotInfo,
    // TODO: change to something that can control the progress or cancel the
    // snapshotting.
    thread: thread::JoinHandle<()>,
}

struct MaybeDbErrors {
    intermediate_trie_error: Cell<Option<Result<()>>>,
    delta_trie_error: Cell<Option<Result<()>>>,
    snapshot_error: Cell<Option<Result<()>>>,
}

// It's only used when relevant lock has been acquired.
unsafe impl Sync for MaybeDbErrors {}

impl StorageManager {
    // FIXME: should load persistent storage from disk.
    pub fn new(
        delta_db_manager: DeltaDbManager, /* , node type, full node or
                                          * archive node */
    ) -> Self
    {
        Self {
            delta_db_manager,
            snapshot_manager: Box::new(StorageManagerFullNode::<
                SnapshotDbManager,
            > {
                // FIXME: path from param.
                snapshot_db_manager: SnapshotDbManager::new(
                    "./storage_db/snapshot/".to_string(),
                ),
            }),
            maybe_db_errors: MaybeDbErrors {
                intermediate_trie_error: Cell::new(None),
                delta_trie_error: Cell::new(None),
                snapshot_error: Cell::new(None),
            },
            snapshot_associated_mpts: RwLock::new(Default::default()),
            in_progress_snapshoting_tasks: Default::default(),
            current_snapshots: Default::default(),
        }
    }

    pub fn get_snapshot_manager(
        &self,
    ) -> &(dyn SnapshotManagerTrait<
        SnapshotDb = SnapshotDb,
        SnapshotDbManager = SnapshotDbManager,
    > + Send
                   + Sync) {
        &*self.snapshot_manager
    }
}

/// Struct which makes sure that the delta mpt is properly ref-counted and
/// released.
pub struct DeltaDbReleaser {
    pub storage_manager: Arc<StorageManager>,
    pub snapshot_root: MerkleHash,
}

impl Drop for DeltaDbReleaser {
    fn drop(&mut self) {
        // FIXME: we must make sure that the latest delta db does not get
        // FIXME: destroyed at program exit. The current code is broken.

        // Note that when an error happens in db, the program should fail
        // gracefully, but not in destructor.
        self.storage_manager
            .release_delta_mpt_actions_in_drop(&self.snapshot_root);
    }
}

impl StorageManager {
    pub fn get_delta_mpt(
        &self, snapshot_root: &MerkleHash,
    ) -> Option<Arc<DeltaMpt>> {
        self.snapshot_associated_mpts
            .read()
            .get(snapshot_root)
            .map(|mpts| mpts.1.clone())
    }

    pub fn new_delta_mpt(
        storage_manager: Arc<StorageManager>, snapshot_root: &MerkleHash,
        intermediate_delta_root: &MerkleHash, conf: StorageConfiguration,
    ) -> Result<Arc<DeltaMpt>>
    {
        let db =
            Arc::new(storage_manager.delta_db_manager.new_empty_delta_db(
                &DeltaDbManager::delta_db_name(snapshot_root),
            )?);
        Ok(Arc::new(DeltaMpt::new(
            db,
            conf,
            DeltaMpt::padding(snapshot_root, intermediate_delta_root),
            snapshot_root.clone(),
            storage_manager.clone(),
        )))
    }

    /// The methods clean up Delta DB when dropping an Delta MPT.
    /// It silently finishes and in case of error, it keeps the error
    /// and raise it later on.
    fn release_delta_mpt_actions_in_drop(&self, snapshot_root: &MerkleHash) {
        let maybe_another_error = self
            .maybe_db_errors
            .intermediate_trie_error
            .replace(Some(self.delta_db_manager.destroy_delta_db(
                &DeltaDbManager::delta_db_name(snapshot_root),
            )));
        self.maybe_db_errors
            .delta_trie_error
            .set(maybe_another_error);
    }

    // FIXME: use,implement snapshot removing logics, check delta mpt lifetime,
    // and maintain snapshot status.
    #[allow(unused)]
    fn release_delta_mpts_from_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        let mut snapshot_associated_mpts_guard =
            self.snapshot_associated_mpts.write();
        // Release
        snapshot_associated_mpts_guard.remove(snapshot_root);
        self.check_db_destroy_errors()
    }

    fn check_db_destroy_errors(&self) -> Result<()> {
        let _maybe_error_1 =
            self.maybe_db_errors.intermediate_trie_error.take();
        let _maybe_error_2 = self.maybe_db_errors.delta_trie_error.take();
        // FIXME: Combine two errors, instruct users, and raise combined error.
        unimplemented!()
    }

    pub fn check_make_register_snapshot_background(
        this: Arc<Self>, old_snapshot_root: &MerkleHash,
        snapshot_epoch_id: EpochId, height: u64, delta_db: DeltaMptInserter,
    ) -> Result<()>
    {
        let this_cloned = this.clone();
        let upgradable_read_locked =
            this_cloned.in_progress_snapshoting_tasks.upgradable_read();

        let delta_merkle_root = delta_db.get_merkle_root();

        let mut pivot_chain_parts =
            vec![Default::default(); SNAPSHOT_EPOCHS_CAPACITY as usize];
        {
            // Calculate pivot chain parts.
            let mpt = &*delta_db.mpt;
            let mut epoch_id = snapshot_epoch_id.clone();
            let mut delta_height = SNAPSHOT_EPOCHS_CAPACITY as usize - 1;
            pivot_chain_parts[delta_height] = epoch_id.clone();
            while delta_height > 0 {
                // FIXME: maybe not unwrap, but throw an error about db
                // corruption.
                epoch_id = mpt.get_parent_epoch(&epoch_id)?.unwrap();
                delta_height -= 1;
                pivot_chain_parts[delta_height] = epoch_id.clone();
            }
        }

        let in_progress_snapshot_info = SnapshotInfo {
            height: height as u64,
            parent_snapshot: old_snapshot_root.clone(),
            parent_snapshot_height: height - SNAPSHOT_EPOCHS_CAPACITY,
            delta_root: delta_merkle_root,
            // This is unknown for now, and we don't care.
            merkle_root: Default::default(),
            pivot_chain_parts,
        };

        if !upgradable_read_locked.contains_key(&snapshot_epoch_id) {
            let mut write_locked =
                RwLockUpgradableReadGuard::upgrade(upgradable_read_locked);
            // FIXME: make snapshot in background..
            // FIXME: the snapshot should contain the partial chain information
            // FIXME: but we figure out how to do it later.
            let old_snapshot_root_cloned = old_snapshot_root.clone();
            let in_progress_snapshot_info_cloned =
                in_progress_snapshot_info.clone();
            let task = thread::Builder::new()
                .name("Background Snapshotting".into()).spawn(move || {
                let result =
                    this.snapshot_manager
                        .get_snapshot_db_manager()
                        .new_snapshot_by_merging(
                            &old_snapshot_root_cloned,
                            snapshot_epoch_id, delta_db,
                            in_progress_snapshot_info_cloned);

                if result.is_ok() {
                    this.register_new_snapshot(result.unwrap());
                } else {
                    // FIXME: log the error.
                    warn!(
                        "Failed to create snapshot for epoch_id {:?} with error {:?}",
                        snapshot_epoch_id, result.as_ref().err());
                    // TODO: improve the cancellation in a better way.
                    // Check for cancellation.
                    if this.in_progress_snapshoting_tasks.
                        read().contains_key(&snapshot_epoch_id) {
                        // FIXME: maybe add more details...
                        this.maybe_db_errors
                            .snapshot_error.replace(Some(result.map(|_| ())));
                    }
                }
            })?;

            write_locked.insert(
                snapshot_epoch_id,
                InProgressSnapshotInfo {
                    snapshot_info: in_progress_snapshot_info,
                    thread: task,
                },
            );
        }

        Ok(())
    }

    fn register_new_snapshot(&self, new_snapshot_info: SnapshotInfo) {
        // FIXME: we extract SnapshotInfo from the snapshot db but later change
        // the prototype.
        let mut current_snapshots = self.current_snapshots.write();
        current_snapshots.push(new_snapshot_info);

        // FIXME: update db about new current_snapshots.
    }

    pub fn maintain_snapshots_pivot_chain_confirmed(
        &self, confirmed_height: u64, confirmed_epoch: &SnapshotAndEpochIdRef,
    ) -> Result<()> {
        // FIXME: save the last confirmed_epoch, and only do sth when the
        // confirmation changes.

        let mut non_pivot_snapshots_to_remove = HashSet::new();
        let mut old_pivot_snapshots_to_remove = vec![];
        let mut in_progress_snapshot_to_cancel = vec![];

        let confirmed_intermediate_height = confirmed_height
            - confirmed_epoch.delta_trie_height.unwrap() as u64;

        {
            let current_snapshots = self.current_snapshots.read();

            let confirmed_snapshot_height =
                confirmed_intermediate_height - SNAPSHOT_EPOCHS_CAPACITY as u64;

            let mut old_pivot_merkle_root =
                confirmed_epoch.previous_snapshot_root;

            // Check snapshots which has height lower than confirmed_height
            for snapshot_info in current_snapshots.iter().rev() {
                if snapshot_info.height == confirmed_snapshot_height {
                    // Remove all non-pivot Snapshot at
                    // confirmed_snapshot_height
                    if !snapshot_info
                        .merkle_root
                        .eq(confirmed_epoch.snapshot_root)
                    {
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_info.merkle_root.clone());
                    }
                } else if snapshot_info.height < confirmed_snapshot_height {
                    // We remove for older pivot snapshot one after another.
                    if snapshot_info.merkle_root.eq(old_pivot_merkle_root) {
                        old_pivot_snapshots_to_remove
                            .push(snapshot_info.merkle_root.clone());
                        old_pivot_merkle_root = &snapshot_info.parent_snapshot;
                    } else {
                        // Any other snapshot with higher height is non-pivot.
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_info.merkle_root.clone());
                    }
                } else if snapshot_info.height < confirmed_height {
                    // There can be at most 1 snapshot between the snapshot at
                    // confirmed_snapshot_height and confirmed_height.
                    //
                    // When a snapshot has height > confirmed_snapshot_height,
                    // but doesn't contain confirmed_epoch.
                    // intermediate_epoch_id, it must be a non-pivot fork.
                    if snapshot_info
                        .get_epoch_id_at_height(confirmed_intermediate_height)
                        != Some(confirmed_epoch.intermediate_epoch_id)
                    {
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_info.merkle_root.clone());
                    }
                }
            }

            // Check snapshots which has height >= confirmed_height
            for snapshot_info in &*current_snapshots {
                // Check for non-pivot snapshot to remove.
                match snapshot_info.get_epoch_id_at_height(confirmed_height) {
                    Some(path_epoch_id) => {
                        // Check if the snapshot is within confirmed_epoch's
                        // subtree.
                        if path_epoch_id != confirmed_epoch.epoch_id {
                            non_pivot_snapshots_to_remove
                                .insert(snapshot_info.merkle_root.clone());
                        }
                    }
                    None => {
                        // The snapshot is so deep that we have to check its
                        // parent to see if it's within confirmed_epoch's
                        // subtree.
                        if non_pivot_snapshots_to_remove
                            .contains(&snapshot_info.parent_snapshot)
                        {
                            non_pivot_snapshots_to_remove
                                .insert(snapshot_info.merkle_root.clone());
                        }
                    }
                }
            }
        }

        for (in_progress_epoch_id, in_progress_snapshot_info) in
            &*self.in_progress_snapshoting_tasks.read()
        {
            let mut to_cancel = false;

            // The logic is similar as above for snapshot deletion.
            if in_progress_snapshot_info.snapshot_info.height
                < confirmed_intermediate_height
            {
                to_cancel = true;
            } else if in_progress_snapshot_info.snapshot_info.height
                < confirmed_height
            {
                if in_progress_snapshot_info
                    .snapshot_info
                    .get_epoch_id_at_height(confirmed_intermediate_height)
                    != Some(confirmed_epoch.intermediate_epoch_id)
                {
                    to_cancel = true;
                }
            } else {
                match in_progress_snapshot_info
                    .snapshot_info
                    .get_epoch_id_at_height(confirmed_height)
                {
                    Some(path_epoch_id) => {
                        if path_epoch_id != confirmed_epoch.epoch_id {
                            to_cancel = true;
                        }
                    }
                    None => {
                        if non_pivot_snapshots_to_remove.contains(
                            &in_progress_snapshot_info
                                .snapshot_info
                                .parent_snapshot,
                        ) {
                            to_cancel = true;
                        }
                    }
                }
            }

            if to_cancel {
                in_progress_snapshot_to_cancel
                    .push(in_progress_epoch_id.clone())
            }
        }

        if !non_pivot_snapshots_to_remove.is_empty()
            || !old_pivot_snapshots_to_remove.is_empty()
        {
            let mut snapshots_to_remove = non_pivot_snapshots_to_remove.clone();

            let mut current_snapshots_locked = self.current_snapshots.write();
            for snapshot_root in old_pivot_snapshots_to_remove {
                self.snapshot_manager
                    .remove_old_pivot_snapshot(&snapshot_root)?;
                snapshots_to_remove.insert(snapshot_root);
            }
            for snapshot_root in non_pivot_snapshots_to_remove {
                self.snapshot_manager
                    .remove_non_pivot_snapshot(&snapshot_root)?;
            }

            current_snapshots_locked
                .retain(|x| !snapshots_to_remove.contains(&x.merkle_root));
        }

        if !in_progress_snapshot_to_cancel.is_empty() {
            let mut in_progress_snapshoting_locked =
                self.in_progress_snapshoting_tasks.write();
            for epoch_id in in_progress_snapshot_to_cancel {
                // TODO: implement cancellation in a better way.
                in_progress_snapshoting_locked.remove(&epoch_id);
            }
        }

        Ok(())
    }
}

// FIXME: remove, because we do things in SnapshotManagerFullNode.
/*
impl GetSnapshotDbManager for StorageManager {
    type SnapshotDb = SnapshotDb;
    type SnapshotDbManager = SnapshotDbManager;

    fn get_snapshot_db_manager(&self) -> &Self::SnapshotDbManager {
        &self.snapshot_manager.get_snapshot_db_manager()
    }
}

impl SnapshotManagerTrait for StorageManager {
    fn remove_old_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        self.release_delta_mpts_from_snapshot(snapshot_root)?;
        self.snapshot_manager
            .remove_old_pivot_snapshot(snapshot_root)
    }

    fn remove_non_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        self.release_delta_mpts_from_snapshot(snapshot_root)?;
        self.snapshot_manager
            .remove_non_pivot_snapshot(snapshot_root)
    }
}
*/

#[derive(Clone)]
pub struct DeltaMptInserter {
    pub mpt: Arc<DeltaMpt>,
    pub maybe_root_node: Option<NodeRefDeltaMpt>,
}

impl DeltaMptInserter {
    pub fn get_merkle_root(&self) -> MerkleHash {
        // FIXME: implement.
        unimplemented!()
    }

    pub fn iterate<'a, DeltaMptDumper: KVInserter<(Vec<u8>, Box<[u8]>)>>(
        &self, mut dumper: DeltaMptDumper,
    ) -> Result<()> {
        match &self.maybe_root_node {
            None => {}
            Some(root_node) => {
                let db = &mut *self.mpt.db_owned_read()?;
                let owned_node_set = Default::default();
                let mut cow_root_node =
                    CowNodeRef::new(root_node.clone(), &owned_node_set);
                let guarded_trie_node =
                    GuardedValue::take(cow_root_node.get_trie_node(
                        self.mpt.get_node_memory_manager(),
                        &self.mpt.get_node_memory_manager().get_allocator(),
                        db,
                    )?);
                cow_root_node.iterate_internal(
                    &owned_node_set,
                    &self.mpt,
                    guarded_trie_node,
                    CompressedPathRaw::new_zeroed(0, 0),
                    &mut dumper,
                    db,
                )?;
            }
        }
        Ok(())
    }
}

use super::{
    super::{
        super::{
            snapshot_manager::*,
            state_manager::*,
            storage_db::{
                delta_db_manager::*, snapshot_db::*,
                snapshot_db_manager::SnapshotDbManagerTrait,
            },
        },
        errors::*,
        multi_version_merkle_patricia_trie::{
            guarded_value::GuardedValue,
            merkle_patricia_trie::{
                cow_node_ref::KVInserter, CompressedPathRaw, CowNodeRef,
                NodeRefDeltaMpt,
            },
            DeltaMpt,
        },
        state_manager::*,
    },
    *,
};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use primitives::{EpochId, MerkleHash};
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    sync::Arc,
    thread,
};
