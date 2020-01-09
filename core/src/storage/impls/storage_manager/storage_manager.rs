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
    delta_mpts_id_gen: Mutex<DeltaMptIdGen>,
    delta_mpts_node_memory_manager: Arc<DeltaMptsNodeMemoryManager>,

    maybe_db_errors: MaybeDbErrors,
    snapshot_associated_mpts_by_epoch: RwLock<
        HashMap<EpochId, (Option<Arc<DeltaMpt>>, Option<Arc<DeltaMpt>>)>,
    >,

    pub in_progress_snapshoting_tasks:
        RwLock<HashMap<EpochId, InProgressSnapshotInfo>>,

    // Db to persist snapshot_info.
    snapshot_info_db: KvdbSqlite<Box<[u8]>>,

    // The order doesn't matter as long as parent snapshot comes before
    // children snapshots.
    // Note that for archive node the list here is just a subset of what's
    // available.
    current_snapshots: RwLock<Vec<SnapshotInfo>>,
    snapshot_info_map_by_epoch: RwLock<HashMap<EpochId, SnapshotInfo>>,

    last_confirmed_snapshotable_epoch_id: Mutex<Option<EpochId>>,

    storage_conf: StorageConfiguration,
}

/// Struct which makes sure that the delta mpt is properly ref-counted and
/// released.
pub struct DeltaDbReleaser {
    pub storage_manager: Weak<StorageManager>,
    pub snapshot_epoch_id: EpochId,
    pub mpt_id: DeltaMptId,
}

impl Drop for DeltaDbReleaser {
    fn drop(&mut self) {
        // Don't drop any delta mpt at graceful shutdown because those remaining
        // DeltaMPTs are useful.

        // Note that when an error happens in db, the program should fail
        // gracefully, but not in destructor.
        Weak::upgrade(&self.storage_manager).map(|storage_manager| {
            storage_manager.release_delta_mpt_actions_in_drop(
                &self.snapshot_epoch_id,
                self.mpt_id,
            )
        });
    }
}

// FIXME: the thread variable is used. But it's subject to refinements for sure.
pub struct InProgressSnapshotInfo {
    snapshot_info: SnapshotInfo,
    // TODO: change to something that can control the progress or cancel the
    // snapshotting.
    pub thread: thread::JoinHandle<()>,
}

impl StorageManager {
    pub fn new_arc(
        /* TODO: Add node type, full node or archive node */
        storage_conf: StorageConfiguration,
    ) -> Result<Arc<Self>>
    {
        let storage_dir = Path::new(storage_conf.path_storage_dir.as_str());
        if !storage_dir.exists() {
            fs::create_dir_all(storage_dir)?;
        }

        let (_, snapshot_info_db) = KvdbSqlite::open_or_create(
            storage_conf.path_snapshot_info_db.clone(),
            SNAPSHOT_KVDB_STATEMENTS.clone(),
        )?;

        let new_storage_manager_result = Ok(Arc::new(Self {
            delta_db_manager: DeltaDbManager::new(
                storage_conf.path_delta_mpts_dir.clone(),
            )?,
            snapshot_manager: Box::new(StorageManagerFullNode::<
                SnapshotDbManager,
            > {
                snapshot_db_manager: SnapshotDbManager::new(
                    storage_conf.path_snapshot_dir.clone(),
                )?,
            }),
            delta_mpts_id_gen: Default::default(),
            delta_mpts_node_memory_manager: Arc::new(
                DeltaMptsNodeMemoryManager::new(
                    storage_conf.delta_mpts_cache_start_size,
                    storage_conf.delta_mpts_cache_size,
                    storage_conf.delta_mpts_slab_idle_size,
                    storage_conf.delta_mpts_node_map_vec_size,
                    DeltaMptsCacheAlgorithm::new(
                        storage_conf.delta_mpts_cache_size,
                    ),
                ),
            ),
            maybe_db_errors: MaybeDbErrors {
                delta_trie_destroy_error_1: Cell::new(None),
                delta_trie_destroy_error_2: Cell::new(None),
                snapshot_error: Cell::new(None),
            },
            snapshot_associated_mpts_by_epoch: Default::default(),
            in_progress_snapshoting_tasks: Default::default(),
            snapshot_info_db,
            current_snapshots: Default::default(),
            snapshot_info_map_by_epoch: Default::default(),
            last_confirmed_snapshotable_epoch_id: Default::default(),
            storage_conf,
        }));

        new_storage_manager_result
            .as_ref()
            .unwrap()
            .load_persist_state()?;

        new_storage_manager_result
    }

    pub fn wait_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Option<SnapshotDb>> {
        match self
            .snapshot_manager
            .get_snapshot_by_epoch_id(snapshot_epoch_id)?
        {
            Some(snapshot_db) => Ok(Some(snapshot_db)),
            None => {
                // Keep the lock while waiting.
                let mut locked = self.in_progress_snapshoting_tasks.write();
                // Wait for in progress snapshot.
                if let Some(in_progress_snapshot_info) =
                    locked.remove(snapshot_epoch_id)
                {
                    in_progress_snapshot_info.thread.join().ok();
                    // FIXME: improve the wait mechanism and throw out errors
                    // FIXME: happened in making snapshot.
                    self.snapshot_manager
                        .get_snapshot_by_epoch_id(snapshot_epoch_id)
                } else {
                    Ok(None)
                }
            }
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

    pub fn get_snapshot_epoch_count(&self) -> u32 {
        self.storage_conf.consensus_param.snapshot_epoch_count
    }

    pub fn get_delta_mpt(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Arc<DeltaMpt>> {
        {
            let snapshot_associated_mpts_locked =
                self.snapshot_associated_mpts_by_epoch.read();
            match snapshot_associated_mpts_locked.get(snapshot_epoch_id) {
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
            &mut *self.snapshot_associated_mpts_by_epoch.write(),
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
        snapshot_associated_mpts_mut: &mut HashMap<
            EpochId,
            (Option<Arc<DeltaMpt>>, Option<Arc<DeltaMpt>>),
        >,
    ) -> Result<Arc<DeltaMpt>>
    {
        // Don't hold the lock while doing db io.
        // FIXME This always succeeds with the same delta_db opened now.
        // If the DeltaMpt already exists, the empty delta db creation should
        // fail already.
        let db_result = storage_manager.delta_db_manager.new_empty_delta_db(
            &storage_manager
                .delta_db_manager
                .get_delta_db_name(snapshot_epoch_id),
        );

        let mut maybe_snapshot_entry =
            snapshot_associated_mpts_mut.get_mut(snapshot_epoch_id);
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

            let arc_delta_mpt = Arc::new(DeltaMpt::new(
                db,
                snapshot_epoch_id.clone(),
                storage_manager.clone(),
                &mut *storage_manager.delta_mpts_id_gen.lock(),
                storage_manager.delta_mpts_node_memory_manager.clone(),
            )?);

            maybe_snapshot_entry.as_mut().unwrap().1 =
                Some(arc_delta_mpt.clone());
            // For Genesis snapshot, the intermediate MPT is the same as the
            // delta MPT.
            if snapshot_epoch_id.eq(&NULL_EPOCH) {
                maybe_snapshot_entry.unwrap().0 = Some(arc_delta_mpt.clone());
            }

            return Ok(arc_delta_mpt);
        }
    }

    /// The methods clean up Delta DB when dropping an Delta MPT.
    /// It silently finishes and in case of error, it keeps the error
    /// and raise it later on.
    fn release_delta_mpt_actions_in_drop(
        &self, snapshot_epoch_id: &EpochId, delta_mpt_id: DeltaMptId,
    ) {
        self.delta_mpts_node_memory_manager
            .delete_mpt_from_cache(delta_mpt_id);
        self.delta_mpts_id_gen.lock().free(delta_mpt_id);
        let maybe_another_error = self
            .maybe_db_errors
            .delta_trie_destroy_error_1
            .replace(Some(self.delta_db_manager.destroy_delta_db(
                &self.delta_db_manager.get_delta_db_name(snapshot_epoch_id),
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
        maybe_delta_db: Option<DeltaMptIterator>,
    ) -> Result<()>
    {
        debug!(
            "check_make_register_snapshot_background: epoch={:?} height={:?}",
            snapshot_epoch_id, height
        );
        let this_cloned = this.clone();
        let mut in_progress_snapshoting_tasks =
            this_cloned.in_progress_snapshoting_tasks.write();

        if !in_progress_snapshoting_tasks.contains_key(&snapshot_epoch_id)
            && !this
                .snapshot_info_map_by_epoch
                .read()
                .contains_key(&snapshot_epoch_id)
        {
            let mut pivot_chain_parts = vec![
                Default::default();
                this.storage_conf.consensus_param.snapshot_epoch_count
                    as usize
            ];
            // Calculate pivot chain parts.
            let mut epoch_id = snapshot_epoch_id.clone();
            let mut delta_height =
                this.storage_conf.consensus_param.snapshot_epoch_count as usize
                    - 1;
            pivot_chain_parts[delta_height] = epoch_id.clone();
            // TODO Handle the special cases better
            let parent_snapshot_epoch_id = if maybe_delta_db.is_none() {
                // The case maybe_delta_db.is_none() means we are at height 0.
                // We set parent_snapshot of NULL to NULL, so that in
                // register_new_snapshot we will move the initial
                // delta_mpt to intermediate_mpt for NULL_EPOCH
                //
                NULL_EPOCH
            } else {
                let delta_db = maybe_delta_db.as_ref().unwrap();
                while delta_height > 0 {
                    // FIXME: maybe not unwrap, but throw an error about db
                    // corruption.
                    epoch_id =
                        delta_db.mpt.get_parent_epoch(&epoch_id)?.unwrap();
                    delta_height -= 1;
                    pivot_chain_parts[delta_height] = epoch_id.clone();
                    trace!("check_make_register_snapshot_background: parent epoch_id={:?}", epoch_id);
                }
                if height
                    == this.storage_conf.consensus_param.snapshot_epoch_count
                        as u64
                {
                    // We need the case height == SNAPSHOT_EPOCHS_CAPACITY
                    // because the snapshot_info for genesis is
                    // stored in NULL_EPOCH. If we do not use the special case,
                    // it will be the epoch_id of genesis.
                    NULL_EPOCH
                } else {
                    delta_db.mpt.get_parent_epoch(&epoch_id)?.unwrap()
                }
            };

            let in_progress_snapshot_info = SnapshotInfo {
                serve_one_step_sync: true,
                height: height as u64,
                parent_snapshot_height: height
                    - this.storage_conf.consensus_param.snapshot_epoch_count
                        as u64,
                // This is unknown for now, and we don't care.
                merkle_root: Default::default(),
                parent_snapshot_epoch_id,
                pivot_chain_parts,
            };

            let parent_snapshot_epoch_id_cloned =
                in_progress_snapshot_info.parent_snapshot_epoch_id.clone();
            let mut in_progress_snapshot_info_cloned =
                in_progress_snapshot_info.clone();
            let task = thread::Builder::new()
                .name("Background Snapshotting".into()).spawn(move || {
                let f = || -> Result<()> {
                    let new_snapshot_info = match maybe_delta_db {
                        None => {
                            in_progress_snapshot_info_cloned.merkle_root = MERKLE_NULL_NODE;
                            Ok(in_progress_snapshot_info_cloned)
                        }
                        Some(delta_db) => {
                            this.snapshot_manager
                                .get_snapshot_db_manager()
                                .new_snapshot_by_merging(
                                    &parent_snapshot_epoch_id_cloned,
                                    snapshot_epoch_id, delta_db,
                                    in_progress_snapshot_info_cloned)
                        }
                    }?;
                    if let Err(e) = this.register_new_snapshot(new_snapshot_info.clone()) {
                        error!(
                            "Failed to register new snapshot {:?} {:?}.",
                            snapshot_epoch_id, new_snapshot_info
                        );
                        bail!(e);
                    }

                    Ok(())
                };

                if let Err(e) = f() {
                    warn!(
                        "Failed to create snapshot for epoch_id {:?} with error {:?}",
                        snapshot_epoch_id, e);
                    // TODO: improve the cancellation in a better way.
                    // Check for cancellation.
                    if this.in_progress_snapshoting_tasks.
                        read().contains_key(&snapshot_epoch_id) {
                        // FIXME: maybe add more details...
                        this.maybe_db_errors
                            .snapshot_error.replace(Some(Err(e)));
                    }
                }

            })?;

            in_progress_snapshoting_tasks.insert(
                snapshot_epoch_id,
                InProgressSnapshotInfo {
                    snapshot_info: in_progress_snapshot_info,
                    thread: task,
                },
            );
        }

        Ok(())
    }

    /// This function is made public only for testing.
    pub fn register_new_snapshot(
        &self, new_snapshot_info: SnapshotInfo,
    ) -> Result<()> {
        debug!("register_new_snapshot: info={:?}", new_snapshot_info);
        let snapshot_epoch_id = new_snapshot_info.get_snapshot_epoch_id();
        // Register intermediate MPT for the new snapshot.
        let mut snapshot_associated_mpts_locked =
            self.snapshot_associated_mpts_by_epoch.write();

        // Parent's delta mpt becomes intermediate_delta_mpt for the new
        // snapshot.
        //
        // It can't happen when the parent's delta mpt is still empty we
        // are already making the snapshot.
        //
        // But when we synced a new snapshot, the parent snapshot may not be
        // available at all, so when maybe_intermediate_delta_mpt is empty,
        // create it.
        let maybe_intermediate_delta_mpt = match snapshot_associated_mpts_locked
            .get(&new_snapshot_info.parent_snapshot_epoch_id)
        {
            None => {
                // The case when we synced a new snapshot and the parent
                // snapshot isn't available.
                snapshot_associated_mpts_locked.insert(
                    new_snapshot_info.parent_snapshot_epoch_id.clone(),
                    (None, None),
                );
                let parent_delta_mpt =
                    Some(StorageManager::new_or_get_delta_mpt(
                        // The StorageManager is maintained in Arc so it's
                        // fine to call
                        // this unsafe function.
                        unsafe { shared_from_this(self) },
                        &new_snapshot_info.parent_snapshot_epoch_id,
                        &mut *snapshot_associated_mpts_locked,
                    )?);
                snapshot_associated_mpts_locked
                    .remove(&new_snapshot_info.parent_snapshot_epoch_id);

                parent_delta_mpt
            }
            Some(parent_snapshot_associated_mpts) => {
                parent_snapshot_associated_mpts.1.clone()
            }
        };
        snapshot_associated_mpts_locked.insert(
            snapshot_epoch_id.clone(),
            (maybe_intermediate_delta_mpt, None),
        );

        self.snapshot_info_map_by_epoch
            .write()
            .insert(snapshot_epoch_id.clone(), new_snapshot_info.clone());
        self.snapshot_info_db
            .put(snapshot_epoch_id.as_ref(), &new_snapshot_info.rlp_bytes())?;
        self.current_snapshots.write().push(new_snapshot_info);

        Ok(())
    }

    /// The algorithm figure out which snapshot to remove by simply going
    /// through all SnapshotInfo in one pass in the reverse order such that
    /// the parent snapshot is processed after the children snapshot.
    ///
    /// In the scan, pivot chain is traced from the confirmed snapshot. Whatever
    /// can't be traced shall be removed as non-pivot snapshot. Traced
    /// old pivot snapshot shall be deleted as well.
    ///
    /// Another maintenance of snapshots shall happen at Conflux start-up and
    /// after pivot chain is recognized.
    ///
    /// The behavior of old pivot snapshot deletion can be different between
    /// Archive Node and Full Node.
    pub fn maintain_snapshots_pivot_chain_confirmed(
        &self, confirmed_height: u64,
        confirmed_snapshotable_epoch_id: &EpochId,
        confirmed_state_root: &StateRootWithAuxInfo,
    ) -> Result<()>
    {
        // Update the confirmed epoch id. Skip remaining actions when the
        // confirmed epoch id doesn't change
        {
            let mut last_confirmed_snapshotable_id_locked =
                self.last_confirmed_snapshotable_epoch_id.lock();
            if last_confirmed_snapshotable_id_locked.is_some() {
                if confirmed_snapshotable_epoch_id
                    .eq(last_confirmed_snapshotable_id_locked.as_ref().unwrap())
                {
                    return Ok(());
                }
            }
            *last_confirmed_snapshotable_id_locked =
                Some(confirmed_snapshotable_epoch_id.clone());
        }

        let mut non_pivot_snapshots_to_remove = HashSet::new();
        let mut old_pivot_snapshots_to_remove = vec![];
        let mut in_progress_snapshot_to_cancel = vec![];

        let confirmed_intermediate_height = confirmed_height
            - StateIndex::height_to_delta_height(
                confirmed_height,
                self.get_snapshot_epoch_count(),
            ) as u64;

        {
            let current_snapshots = self.current_snapshots.read();

            let confirmed_snapshot_height = if confirmed_intermediate_height
                > self.storage_conf.consensus_param.snapshot_epoch_count as u64
            {
                confirmed_intermediate_height
                    - self.storage_conf.consensus_param.snapshot_epoch_count
                        as u64
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
                        if path_epoch_id != confirmed_snapshotable_epoch_id {
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
                        if path_epoch_id != confirmed_snapshotable_epoch_id {
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
            for snapshot_epoch_id in snapshots_to_remove {
                self.snapshot_info_db.delete(snapshot_epoch_id.as_ref())?;
            }
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

    pub fn get_snapshot_info_at_epoch(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<SnapshotInfo> {
        self.snapshot_info_map_by_epoch
            .read()
            .get(snapshot_epoch_id)
            .map(Clone::clone)
    }

    /// FIXME Enable later.
    pub fn log_usage(&self) {
        // FIXME: log usage for all delta mpt.
        // Log the usage of the delta mpt for the first snapshot.
        // FIXME: due to initialization problems the delta mpt may not be
        // available?
        //        self.snapshot_associated_mpts_by_epoch
        //            .read()
        //            .get(&NULL_EPOCH)
        //            .unwrap()
        //            .1
        //            .as_ref()
        //            .unwrap()
        //            .log_usage();
    }

    pub fn load_persist_state(&self) -> Result<()> {
        let snapshot_info_map = &mut *self.snapshot_info_map_by_epoch.write();
        // Load snapshot info from db.
        {
            let mut new_db = self.snapshot_info_db.try_clone()?;
            let mut snapshot_info_db_iter = ConnectionWithRowParser::<
                KvdbSqliteBorrowMutReadOnly<Box<[u8]>>,
                Box<
                    dyn for<'db> FnMut(
                        &'db Statement,
                    )
                        -> Result<(Vec<u8>, Vec<u8>)>,
                >,
            >(
                KvdbSqliteBorrowMutReadOnly::new(
                    // FIXME: refactor so that a KeyValueDbMultiReader can be
                    // iterate without a mut borrow.
                    new_db.destructure_mut(),
                ),
                // FIXME: it's confused to use a parser for SnapshotDbSqlite.
                Box::new(|x| SnapshotDbSqlite::snapshot_kv_row_parser(x)),
            );
            let mut snapshot_info_iter = snapshot_info_db_iter
                .iter_range(&[], None)?
                .map(|(key, value)| {
                    if key.len() != EpochId::len_bytes() {
                        Err(DecoderError::RlpInvalidLength.into())
                    } else {
                        Ok((
                            EpochId::from_slice(&key),
                            SnapshotInfo::decode(&Rlp::new(&value))?,
                        ))
                    }
                });
            // FIXME: refactor iterator. ConnectionWithRowParser is superfluous.
            while let Some((snapshot_epoch, snapshot_info)) =
                snapshot_info_iter.next()?
            {
                snapshot_info_map.insert(snapshot_epoch, snapshot_info);
            }
        }

        // Always keep the information for genesis snapshot.
        self.snapshot_associated_mpts_by_epoch
            .write()
            .insert(NULL_EPOCH, (None, None));
        snapshot_info_map
            .insert(NULL_EPOCH, SnapshotInfo::genesis_snapshot_info());
        self.snapshot_info_db.put(
            NULL_EPOCH.as_ref(),
            &SnapshotInfo::genesis_snapshot_info().rlp_bytes(),
        )?;
        self.current_snapshots
            .write()
            .push(SnapshotInfo::genesis_snapshot_info());

        if snapshot_info_map.len() > 0 {
            // Persist state loaded.
            let missing_snapshots = self
                .snapshot_manager
                .get_snapshot_db_manager()
                .scan_persist_state(snapshot_info_map)?;

            // Remove missing snapshots.
            for snapshot_epoch_id in missing_snapshots {
                if snapshot_epoch_id == NULL_EPOCH {
                    continue;
                }
                let snapshot_info =
                    snapshot_info_map.remove(&snapshot_epoch_id);
                error!(
                    "Missing snapshot db: {:?} {:?}",
                    snapshot_epoch_id, snapshot_info
                );
                self.snapshot_info_db.delete(snapshot_epoch_id.as_ref())?;
                self.delta_db_manager.destroy_delta_db(
                    &self
                        .delta_db_manager
                        .get_delta_db_name(&snapshot_epoch_id),
                )?;
            }

            let (missing_snapshots, delta_dbs) = self
                .delta_db_manager
                .scan_persist_state(snapshot_info_map)?;

            let mut delta_mpts = HashMap::new();
            for (snapshot_epoch_id, delta_db) in delta_dbs {
                delta_mpts.insert(
                    snapshot_epoch_id.clone(),
                    Arc::new(DeltaMpt::new(
                        Arc::new(delta_db),
                        snapshot_epoch_id.clone(),
                        unsafe { shared_from_this(self) },
                        &mut *self.delta_mpts_id_gen.lock(),
                        self.delta_mpts_node_memory_manager.clone(),
                    )?),
                );
            }

            for snapshot_epoch_id in missing_snapshots {
                if snapshot_epoch_id == NULL_EPOCH {
                    continue;
                }
                error!(
                    "Missing delta mpt for snapshot {:?}",
                    snapshot_epoch_id
                );
                snapshot_info_map.remove(&snapshot_epoch_id);
                self.snapshot_info_db.delete(snapshot_epoch_id.as_ref())?;
                self.snapshot_manager
                    .get_snapshot_db_manager()
                    .destroy_snapshot(&snapshot_epoch_id)?;
            }

            // Restore current_snapshots.
            let mut snapshots = snapshot_info_map
                .iter()
                .map(|(_, snapshot_info)| snapshot_info.clone())
                .collect::<Vec<_>>();
            snapshots.sort_by(|x, y| x.height.partial_cmp(&y.height).unwrap());

            let current_snapshots = &mut *self.current_snapshots.write();
            std::mem::replace(current_snapshots, snapshots);

            let snapshot_associated_mpts =
                &mut *self.snapshot_associated_mpts_by_epoch.write();
            for snapshot_info in current_snapshots {
                snapshot_associated_mpts.insert(
                    snapshot_info.get_snapshot_epoch_id().clone(),
                    (
                        delta_mpts
                            .get(&snapshot_info.parent_snapshot_epoch_id)
                            .map(|x| x.clone()),
                        delta_mpts
                            .get(snapshot_info.get_snapshot_epoch_id())
                            .map(|x| x.clone()),
                    ),
                );
            }
        }

        Ok(())
    }
}

struct MaybeDbErrors {
    delta_trie_destroy_error_1: Cell<Option<Result<()>>>,
    delta_trie_destroy_error_2: Cell<Option<Result<()>>>,
    snapshot_error: Cell<Option<Result<()>>>,
}

// It's only used when relevant lock has been acquired.
unsafe impl Sync for MaybeDbErrors {}

lazy_static! {
    static ref SNAPSHOT_KVDB_STATEMENTS: Arc<KvdbSqliteStatements> = Arc::new(
        KvdbSqliteStatements::make_statements(
            &["value"],
            &["BLOB"],
            StorageConfiguration::SNAPSHOT_INFO_DB_NAME,
            false
        )
        .unwrap()
    );
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
            utils::arc_ext::*,
            StateRootWithAuxInfo,
        },
        delta_mpt::*,
        errors::*,
        state_manager::*,
    },
    *,
};
use crate::storage::{
    impls::{
        delta_mpt::{
            node_memory_manager::{
                DeltaMptsCacheAlgorithm, DeltaMptsNodeMemoryManager,
            },
            node_ref_map::DeltaMptId,
        },
        storage_db::{
            kvdb_sqlite::{
                KvdbSqliteBorrowMutReadOnly, KvdbSqliteDestructureTrait,
                KvdbSqliteStatements,
            },
            snapshot_db_sqlite::SnapshotDbSqlite,
            sqlite::ConnectionWithRowParser,
        },
    },
    storage_db::KeyValueDbIterableTrait,
    KeyValueDbTrait, KvdbSqlite, StorageConfiguration,
};
use fallible_iterator::FallibleIterator;
use parking_lot::{Mutex, RwLock};
use primitives::{EpochId, MERKLE_NULL_NODE, NULL_EPOCH};
use rlp::{Decodable, DecoderError, Encodable, Rlp};
use sqlite::Statement;
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    sync::{Arc, Weak},
    thread,
};
