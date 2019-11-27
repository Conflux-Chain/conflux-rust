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
    snapshot_associated_mpts_by_epoch: RwLock<
        HashMap<EpochId, (Option<Arc<DeltaMpt>>, Option<Arc<DeltaMpt>>)>,
    >,

    in_progress_snapshoting_tasks:
        RwLock<HashMap<EpochId, InProgressSnapshotInfo>>,
    // FIXME: persistent in db.
    // The order doesn't matter as long as parent snapshot comes before
    // children snapshots.
    // Note that for archive node the list here is just a subset of what's
    // available.
    current_snapshots: RwLock<Vec<SnapshotInfo>>,
    snapshot_info_map_by_epoch: RwLock<HashMap<EpochId, SnapshotInfo>>,

    last_confirmed_snapshot_id: Mutex<Option<EpochId>>,

    storage_conf: StorageConfiguration,
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
    delta_trie_destroy_error_1: Cell<Option<Result<()>>>,
    delta_trie_destroy_error_2: Cell<Option<Result<()>>>,
    snapshot_error: Cell<Option<Result<()>>>,
}

// It's only used when relevant lock has been acquired.
unsafe impl Sync for MaybeDbErrors {}

impl StorageManager {
    // FIXME: should load persistent storage from disk.
    pub fn new(
        delta_db_manager: DeltaDbManager, /* , node type, full node or
                                           * archive node */
        storage_conf: StorageConfiguration,
    ) -> Self
    {
        let storage_manager = Self {
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
                delta_trie_destroy_error_1: Cell::new(None),
                delta_trie_destroy_error_2: Cell::new(None),
                snapshot_error: Cell::new(None),
            },
            snapshot_associated_mpts_by_epoch: Default::default(),
            in_progress_snapshoting_tasks: Default::default(),
            current_snapshots: Default::default(),
            snapshot_info_map_by_epoch: Default::default(),
            last_confirmed_snapshot_id: Default::default(),
            storage_conf,
        };

        // Create and register the initial empty snapshot for genesis block
        // and blocks before the second snapshot.
        let genesis_snapshot_info = SnapshotInfo::genesis_snapshot_info();
        storage_manager.register_new_snapshot(genesis_snapshot_info);

        storage_manager
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
    pub storage_manager: Weak<StorageManager>,
    pub snapshot_epoch_id: EpochId,
}

impl Drop for DeltaDbReleaser {
    fn drop(&mut self) {
        // Don't drop any delta mpt at graceful shutdown because those remaining
        // DeltaMPTs are useful.

        // Note that when an error happens in db, the program should fail
        // gracefully, but not in destructor.
        Weak::upgrade(&self.storage_manager).map(|storage_manager| {
            storage_manager
                .release_delta_mpt_actions_in_drop(&self.snapshot_epoch_id)
        });
    }
}

impl StorageManager {
    pub fn get_delta_mpt(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Arc<DeltaMpt>> {
        {
            let snapshot_mpts_locked =
                self.snapshot_associated_mpts_by_epoch.read();
            match snapshot_mpts_locked.get(snapshot_epoch_id) {
                None => bail!(ErrorKind::DeltaMPTEntryNotFound),
                Some(delta_mpts) => {
                    if delta_mpts.1.is_some() {
                        return Ok(delta_mpts.1.as_ref().unwrap().clone());
                    }
                }
            }
        }

        StorageManager::new_or_get_delta_mpt(
            // The StorageManager is maintained in Arc so it's fine to call
            // this unsafe function.
            unsafe { shared_from_this(self) },
            snapshot_epoch_id,
        )
    }

    pub fn get_intermediate_mpt(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Option<Arc<DeltaMpt>>> {
        match self
            .snapshot_associated_mpts_by_epoch
            .read()
            .get(snapshot_epoch_id)
        {
            None => bail!(ErrorKind::DeltaMPTEntryNotFound),
            Some(mpts) => Ok(mpts.0.clone()),
        }
    }

    /// Return the existing delta mpt if the delta mpt already exists.
    pub fn new_or_get_delta_mpt(
        storage_manager: Arc<StorageManager>, snapshot_epoch_id: &EpochId,
    ) -> Result<Arc<DeltaMpt>> {
        // Don't hold the lock while doing db io.
        {
            let snapshot_associated_mpts_locked =
                storage_manager.snapshot_associated_mpts_by_epoch.read();
            let maybe_snapshot_entry =
                snapshot_associated_mpts_locked.get(snapshot_epoch_id);
            if maybe_snapshot_entry.is_none() {
                bail!(ErrorKind::SnapshotNotFound);
            };
            // DeltaMpt already exists
            if maybe_snapshot_entry.unwrap().1.is_some() {
                return Ok(maybe_snapshot_entry
                    .unwrap()
                    .1
                    .as_ref()
                    .unwrap()
                    .clone());
            }
        }

        // If the DeltaMpt already exists, the empty delta db creation should
        // fail already.
        let db_result = storage_manager.delta_db_manager.new_empty_delta_db(
            &DeltaDbManager::delta_db_name(snapshot_epoch_id),
        );

        let mut snapshot_associated_mpts_locked =
            storage_manager.snapshot_associated_mpts_by_epoch.write();
        let maybe_snapshot_entry =
            snapshot_associated_mpts_locked.get_mut(snapshot_epoch_id);
        if maybe_snapshot_entry.is_none() {
            bail!(ErrorKind::SnapshotNotFound);
        };
        // DeltaMpt already exists
        if maybe_snapshot_entry.as_ref().unwrap().1.is_some() {
            return Ok(maybe_snapshot_entry
                .unwrap()
                .1
                .as_ref()
                .unwrap()
                .clone());
        } else {
            let db = Arc::new(db_result?);

            // FIXME: implement delta mpt so that multiple of them coexists.
            let arc_delta_mpt = Arc::new(DeltaMpt::new(
                db,
                &storage_manager.storage_conf,
                snapshot_epoch_id.clone(),
                storage_manager.clone(),
            ));

            maybe_snapshot_entry.unwrap().1 = Some(arc_delta_mpt.clone());

            return Ok(arc_delta_mpt);
        }
    }

    /// The methods clean up Delta DB when dropping an Delta MPT.
    /// It silently finishes and in case of error, it keeps the error
    /// and raise it later on.
    fn release_delta_mpt_actions_in_drop(&self, snapshot_epoch_id: &EpochId) {
        let maybe_another_error = self
            .maybe_db_errors
            .delta_trie_destroy_error_1
            .replace(Some(self.delta_db_manager.destroy_delta_db(
                &DeltaDbManager::delta_db_name(snapshot_epoch_id),
            )));
        self.maybe_db_errors
            .delta_trie_destroy_error_2
            .set(maybe_another_error);
    }

    // FIXME: use snapshot removing logics, check delta mpt lifetime,
    // FIXME: and maintain snapshot status.
    #[allow(unused)]
    fn release_delta_mpts_from_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<()> {
        let mut snapshot_associated_mpts_guard =
            self.snapshot_associated_mpts_by_epoch.write();
        // Release
        snapshot_associated_mpts_guard.remove(snapshot_epoch_id);
        self.check_db_destroy_errors()
    }

    fn check_db_destroy_errors(&self) -> Result<()> {
        let _maybe_error_1 =
            self.maybe_db_errors.delta_trie_destroy_error_1.take();
        let _maybe_error_2 =
            self.maybe_db_errors.delta_trie_destroy_error_2.take();
        // FIXME: Combine two errors, instruct users, and raise combined error.
        unimplemented!()
    }

    pub fn check_make_register_snapshot_background(
        this: Arc<Self>, snapshot_epoch_id: EpochId, height: u64,
        delta_db: DeltaMptInserter,
    ) -> Result<()>
    {
        let this_cloned = this.clone();
        let upgradable_read_locked =
            this_cloned.in_progress_snapshoting_tasks.upgradable_read();

        let mut pivot_chain_parts =
            vec![Default::default(); SNAPSHOT_EPOCHS_CAPACITY as usize];
        let parent_snapshot_epoch_id;
        {
            // Calculate pivot chain parts.
            let mpt = delta_db.maybe_mpt.as_ref().unwrap();
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
            parent_snapshot_epoch_id =
                mpt.get_parent_epoch(&epoch_id)?.unwrap();
        }

        let in_progress_snapshot_info = SnapshotInfo {
            serve_one_step_sync: true,
            height: height as u64,
            parent_snapshot_height: height - SNAPSHOT_EPOCHS_CAPACITY,
            // This is unknown for now, and we don't care.
            merkle_root: Default::default(),
            parent_snapshot_epoch_id,
            pivot_chain_parts,
        };

        if !upgradable_read_locked.contains_key(&snapshot_epoch_id) {
            let mut write_locked =
                RwLockUpgradableReadGuard::upgrade(upgradable_read_locked);
            let parent_snapshot_epoch_id_cloned =
                in_progress_snapshot_info.parent_snapshot_epoch_id.clone();
            let in_progress_snapshot_info_cloned =
                in_progress_snapshot_info.clone();
            let task = thread::Builder::new()
                .name("Background Snapshotting".into()).spawn(move || {
                let result =
                    this.snapshot_manager
                        .get_snapshot_db_manager()
                        .new_snapshot_by_merging(
                            &parent_snapshot_epoch_id_cloned,
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
        // FIXME: update db about new current_snapshots.

        let snapshot_epoch_id = new_snapshot_info.get_snapshot_epoch_id();
        if snapshot_epoch_id.eq(&NULL_EPOCH) {
            // Special case for the very first empty snapshot.
            let mut snapshot_associated_mpts_locked =
                self.snapshot_associated_mpts_by_epoch.write();
            snapshot_associated_mpts_locked
                .insert(snapshot_epoch_id.clone(), (None, None));
        } else {
            // Register intermediate MPT for the new snapshot.
            let mut snapshot_associated_mpts_locked =
                self.snapshot_associated_mpts_by_epoch.write();
            // Parent's delta mpt becomes intermediate_delta_mpt for the new
            // snapshot.
            //
            // It can't happen when the parent's delta mpt is still empty we
            // are already making the snapshot.
            let intermediate_delta_mpt = snapshot_associated_mpts_locked
                .get(&new_snapshot_info.parent_snapshot_epoch_id)
                .unwrap()
                .1
                .clone();
            snapshot_associated_mpts_locked.insert(
                snapshot_epoch_id.clone(),
                (intermediate_delta_mpt, None),
            );
        }

        let mut snapshot_info_map = self.snapshot_info_map_by_epoch.write();
        snapshot_info_map
            .insert(snapshot_epoch_id.clone(), new_snapshot_info.clone());
        let mut current_snapshots = self.current_snapshots.write();
        current_snapshots.push(new_snapshot_info);
    }

    pub fn maintain_snapshots_pivot_chain_confirmed(
        &self, confirmed_height: u64, confirmed_epoch_id: &EpochId,
        confirmed_state_root: &StateRootWithAuxInfo,
    ) -> Result<()>
    {
        {
            let mut last_confirmed_epoch_id_locked =
                self.last_confirmed_snapshot_id.lock();
            if last_confirmed_epoch_id_locked.is_some() {
                if confirmed_epoch_id
                    .eq(last_confirmed_epoch_id_locked.as_ref().unwrap())
                {
                    return Ok(());
                }
            }
            *last_confirmed_epoch_id_locked = Some(confirmed_epoch_id.clone());
        }

        let mut non_pivot_snapshots_to_remove = HashSet::new();
        let mut old_pivot_snapshots_to_remove = vec![];
        let mut in_progress_snapshot_to_cancel = vec![];

        let confirmed_intermediate_height =
            confirmed_height - height_to_delta_height(confirmed_height) as u64;

        {
            let current_snapshots = self.current_snapshots.read();

            let confirmed_snapshot_height = if confirmed_intermediate_height
                > SNAPSHOT_EPOCHS_CAPACITY
            {
                confirmed_intermediate_height - SNAPSHOT_EPOCHS_CAPACITY as u64
            } else {
                0
            };

            let mut prev_snapshot_epoch_id = &NULL_EPOCH;

            // Check snapshots which has height lower than confirmed_height
            for snapshot_info in current_snapshots.iter().rev() {
                let snapshot_epoch_id = snapshot_info.get_snapshot_epoch_id();
                if snapshot_info.height == confirmed_snapshot_height {
                    // Remove all non-pivot Snapshot at
                    // confirmed_snapshot_height
                    if snapshot_epoch_id
                        .eq(&confirmed_state_root.aux_info.snapshot_epoch_id)
                    {
                        prev_snapshot_epoch_id =
                            &snapshot_info.parent_snapshot_epoch_id;
                    } else {
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_epoch_id.clone());
                    }
                } else if snapshot_info.height < confirmed_snapshot_height {
                    // We remove for older pivot snapshot one after another.
                    if snapshot_epoch_id.eq(prev_snapshot_epoch_id) {
                        old_pivot_snapshots_to_remove
                            .push(snapshot_epoch_id.clone());
                        prev_snapshot_epoch_id =
                            &snapshot_info.parent_snapshot_epoch_id;
                    } else {
                        // Any other snapshot with higher height is non-pivot.
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_epoch_id.clone());
                    }
                } else if snapshot_info.height < confirmed_height {
                    // There can be at most 1 snapshot between the snapshot at
                    // confirmed_snapshot_height and confirmed_height.
                    //
                    // When a snapshot has height > confirmed_snapshot_height,
                    // but doesn't contain confirmed_state_root.aux_info.
                    // intermediate_epoch_id, it must be a non-pivot fork.
                    if snapshot_info
                        .get_epoch_id_at_height(confirmed_intermediate_height)
                        != Some(
                            &confirmed_state_root
                                .aux_info
                                .intermediate_epoch_id,
                        )
                    {
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_epoch_id.clone());
                    }
                }
            }

            // Check snapshots which has height >= confirmed_height
            for snapshot_info in &*current_snapshots {
                // Check for non-pivot snapshot to remove.
                match snapshot_info.get_epoch_id_at_height(confirmed_height) {
                    Some(path_epoch_id) => {
                        // Check if the snapshot is within
                        // confirmed_epoch's
                        // subtree.
                        if path_epoch_id != confirmed_epoch_id {
                            non_pivot_snapshots_to_remove.insert(
                                snapshot_info.get_snapshot_epoch_id().clone(),
                            );
                        }
                    }
                    None => {
                        // The snapshot is so deep that we have to check its
                        // parent to see if it's within confirmed_epoch's
                        // subtree.
                        if non_pivot_snapshots_to_remove
                            .contains(&snapshot_info.parent_snapshot_epoch_id)
                        {
                            non_pivot_snapshots_to_remove.insert(
                                snapshot_info.get_snapshot_epoch_id().clone(),
                            );
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
                    != Some(
                        &confirmed_state_root.aux_info.intermediate_epoch_id,
                    )
                {
                    to_cancel = true;
                }
            } else {
                match in_progress_snapshot_info
                    .snapshot_info
                    .get_epoch_id_at_height(confirmed_height)
                {
                    Some(path_epoch_id) => {
                        if path_epoch_id != confirmed_epoch_id {
                            to_cancel = true;
                        }
                    }
                    None => {
                        if non_pivot_snapshots_to_remove.contains(
                            &in_progress_snapshot_info
                                .snapshot_info
                                .parent_snapshot_epoch_id,
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
            for snapshot_epoch_id in old_pivot_snapshots_to_remove {
                self.snapshot_manager
                    .remove_old_pivot_snapshot(&snapshot_epoch_id)?;
                snapshots_to_remove.insert(snapshot_epoch_id);
            }
            for snapshot_epoch_id in non_pivot_snapshots_to_remove {
                self.snapshot_manager
                    .remove_non_pivot_snapshot(&snapshot_epoch_id)?;
            }

            current_snapshots_locked.retain(|x| {
                !snapshots_to_remove.contains(x.get_snapshot_epoch_id())
            });
            self.snapshot_info_map_by_epoch.write().retain(
                |snapshot_epoch_id, _| {
                    !snapshots_to_remove.contains(snapshot_epoch_id)
                },
            );
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

    pub fn log_usage(&self) {
        // FIXME: log usage for all delta mpt.
        // Log the usage of the delta mpt for the first snapshot.
        // FIXME: due to initialization problems the delta mpt may not be
        // available?
        self.snapshot_associated_mpts_by_epoch
            .read()
            .get(&NULL_EPOCH)
            .unwrap()
            .1
            .as_ref()
            .unwrap()
            .log_usage();
    }
}

#[derive(Clone)]
pub struct DeltaMptInserter {
    pub maybe_mpt: Option<Arc<DeltaMpt>>,
    pub maybe_root_node: Option<NodeRefDeltaMpt>,
}

impl DeltaMptInserter {
    pub fn get_merkle_root(&self) -> MerkleHash {
        // FIXME: implement.
        unimplemented!()
    }

    pub fn iterate<'a, DeltaMptDumper: KVInserter<(Vec<u8>, Box<[u8]>)>>(
        &self, dumper: &mut DeltaMptDumper,
    ) -> Result<()> {
        match &self.maybe_root_node {
            None => {}
            Some(root_node) => {
                let mpt = self.maybe_mpt.as_ref().unwrap();
                let db = &mut *mpt.db_owned_read()?;
                let owned_node_set = Default::default();
                let mut cow_root_node =
                    CowNodeRef::new(root_node.clone(), &owned_node_set);
                let guarded_trie_node =
                    GuardedValue::take(cow_root_node.get_trie_node(
                        mpt.get_node_memory_manager(),
                        &mpt.get_node_memory_manager().get_allocator(),
                        db,
                    )?);
                cow_root_node.iterate_internal(
                    &owned_node_set,
                    mpt,
                    guarded_trie_node,
                    CompressedPathRaw::new_zeroed(0, 0),
                    dumper,
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
            utils::{arc_ext::*, guarded_value::GuardedValue},
            StateRootWithAuxInfo,
        },
        delta_mpt::*,
        errors::*,
        merkle_patricia_trie::{CompressedPathRaw, KVInserter},
        state_manager::*,
    },
    *,
};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use primitives::{EpochId, MerkleHash, NULL_EPOCH};
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    sync::{Arc, Weak},
    thread,
};
