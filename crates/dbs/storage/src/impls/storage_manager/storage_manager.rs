// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The in mem snapshot_info map and the on disk snapshot_info_db is always in
/// sync.
pub struct PersistedSnapshotInfoMap {
    // Db to persist snapshot_info.
    snapshot_info_db: KvdbSqlite<Box<[u8]>>,
    // In memory snapshot_info_map_by_epoch.
    snapshot_info_map_by_epoch: HashMap<EpochId, SnapshotInfo>,
}

impl PersistedSnapshotInfoMap {
    fn new(snapshot_info_db: KvdbSqlite<Box<[u8]>>) -> Result<Self> {
        let mut result = Self {
            // The map is loaded later
            snapshot_info_map_by_epoch: Default::default(),
            snapshot_info_db,
        };
        result.load_persist_state()?;
        Ok(result)
    }

    fn insert(
        &mut self, epoch: &EpochId, snapshot_info: SnapshotInfo,
    ) -> Result<()> {
        let rlp_bytes = snapshot_info.rlp_bytes();
        self.snapshot_info_map_by_epoch
            .insert(epoch.clone(), snapshot_info);
        self.snapshot_info_db.put(epoch.as_ref(), &rlp_bytes)?;
        Ok(())
    }

    fn get_map(&self) -> &HashMap<EpochId, SnapshotInfo> {
        &self.snapshot_info_map_by_epoch
    }

    fn get(&self, epoch: &EpochId) -> Option<&SnapshotInfo> {
        self.snapshot_info_map_by_epoch.get(epoch)
    }

    fn remove(&mut self, epoch: &EpochId) -> Result<()> {
        self.snapshot_info_map_by_epoch.remove(epoch);
        self.snapshot_info_db.delete(epoch.as_ref())?;
        Ok(())
    }

    // Unsafe because the in mem map isn't in sync with the db.
    unsafe fn remove_in_mem_only(
        &mut self, epoch: &EpochId,
    ) -> Option<SnapshotInfo> {
        self.snapshot_info_map_by_epoch.remove(epoch)
    }

    fn load_persist_state(&mut self) -> Result<()> {
        // Load snapshot info from db.
        let (maybe_info_db_connection, statements) =
            self.snapshot_info_db.destructure_mut();

        let mut snapshot_info_iter = kvdb_sqlite_iter_range_impl(
            maybe_info_db_connection,
            statements,
            &[],
            None,
            |row: &Statement<'_>| {
                let key = row.read::<Vec<u8>>(0)?;
                let value = row.read::<Vec<u8>>(1)?;

                if key.len() != EpochId::len_bytes() {
                    Err(DecoderError::RlpInvalidLength.into())
                } else {
                    Ok((
                        EpochId::from_slice(&key),
                        SnapshotInfo::decode(&Rlp::new(&value))?,
                    ))
                }
            },
        )?;
        while let Some((snapshot_epoch, snapshot_info)) =
            snapshot_info_iter.next()?
        {
            self.snapshot_info_map_by_epoch
                .insert(snapshot_epoch, snapshot_info);
        }
        Ok(())
    }
}

// FIXME: correctly order code blocks.
pub struct StorageManager {
    delta_db_manager: Arc<DeltaDbManager>,
    delta_mpt_open_db_lru: Arc<OpenDeltaDbLru<DeltaDbManager>>,
    snapshot_manager: Box<
        dyn SnapshotManagerTrait<
                SnapshotDb = SnapshotDb,
                SnapshotDbManager = SnapshotDbManager,
            > + Send
            + Sync,
    >,
    delta_mpts_id_gen: Mutex<DeltaMptIdGen>,
    delta_mpts_node_memory_manager: Arc<DeltaMptsNodeMemoryManager>,

    maybe_db_errors: MaybeDeltaTrieDestroyErrors,
    snapshot_associated_mpts_by_epoch: RwLock<
        HashMap<EpochId, (Option<Arc<DeltaMpt>>, Option<Arc<DeltaMpt>>)>,
    >,

    // Lock order: while this is locked, in
    // check_make_register_snapshot_background, snapshot_info_map_by_epoch
    // is locked later.
    pub in_progress_snapshotting_tasks:
        RwLock<HashMap<EpochId, Arc<RwLock<InProgressSnapshotTask>>>>,
    in_progress_snapshot_finish_signaler: Arc<Mutex<Sender<Option<EpochId>>>>,
    in_progress_snapshotting_joiner: Mutex<Option<JoinHandle<()>>>,

    // The order doesn't matter as long as parent snapshot comes before
    // children snapshots.
    // Note that for archive node the list here is just a subset of what's
    // available.
    //
    // Lock order: while this is locked, in load_persist_state and
    // state_manager.rs:get_state_trees_for_next_epoch
    // snapshot_associated_mpts_by_epoch is locked later.
    current_snapshots: RwLock<Vec<SnapshotInfo>>,
    // Lock order: while this is locked, in register_new_snapshot and
    // load_persist_state, current_snapshots and
    // snapshot_associated_mpts_by_epoch are locked later.
    pub snapshot_info_map_by_epoch: RwLock<PersistedSnapshotInfoMap>,

    last_confirmed_snapshottable_epoch_id: Mutex<Option<EpochId>>,

    pub storage_conf: StorageConfiguration,

    // used during startup for the next compute epoch
    pub intermediate_trie_root_merkle: RwLock<Option<MerkleHash>>,

    pub persist_state_from_initialization:
        RwLock<Option<(Option<EpochId>, HashSet<EpochId>, u64, Option<u64>)>>,
}

impl MallocSizeOf for StorageManager {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        // TODO: Sqlite for snapshot may also use a significant amount of
        // memory. We need to fork the crate `sqlite` ourselves to
        // expose `sqlite3_status` to get the memory usage statistics.
        let mut size = 0;
        size += self.delta_mpts_node_memory_manager.size_of(ops);
        size += self.snapshot_associated_mpts_by_epoch.size_of(ops);
        size
    }
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

// TODO: Add support for cancellation and io throttling.
pub struct InProgressSnapshotTask {
    snapshot_info: SnapshotInfo,
    thread_handle: Option<thread::JoinHandle<Result<()>>>,
}

impl InProgressSnapshotTask {
    // Returns None if the thread has been joined already. Returns the
    // background snapshotting result when the thread is first joined.
    pub fn join(&mut self) -> Option<Result<()>> {
        if let Some(join_handle) = self.thread_handle.take() {
            match join_handle.join() {
                Ok(task_result) => Some(task_result),
                Err(_) => Some(Err(Error::ThreadPanicked(format!(
                    "Background Snapshotting for {:?} panicked.",
                    self.snapshot_info
                ))
                .into())),
            }
        } else {
            None
        }
    }
}

impl StorageManager {
    pub fn new_arc(
        /* TODO: Add node type, full node or archive node */
        storage_conf: StorageConfiguration,
    ) -> Result<Arc<Self>> {
        let storage_dir = storage_conf.path_storage_dir.as_path();
        debug!(
            "new StorageManager within storage_dir {}",
            storage_dir.display()
        );
        if !storage_dir.exists() {
            fs::create_dir_all(storage_dir)?;
        }

        let (_, snapshot_info_db) = KvdbSqlite::open_or_create(
            &storage_conf.path_snapshot_info_db,
            SNAPSHOT_KVDB_STATEMENTS.clone(),
            false, /* unsafe_mode */
        )?;
        let snapshot_info_map =
            PersistedSnapshotInfoMap::new(snapshot_info_db)?;

        let (
            in_progress_snapshot_finish_signaler,
            in_progress_snapshot_finish_signal_receiver,
        ) = channel();

        let delta_db_manager = Arc::new(DeltaDbManager::new(
            storage_conf.path_delta_mpts_dir.clone(),
        )?);
        let new_storage_manager_result = Ok(Arc::new(Self {
            delta_db_manager: delta_db_manager.clone(),
            delta_mpt_open_db_lru: Arc::new(OpenDeltaDbLru::new(
                delta_db_manager.clone(),
                storage_conf.max_open_mpt_count,
            )?),
            snapshot_manager: Box::new(SnapshotManager::<SnapshotDbManager> {
                snapshot_db_manager: SnapshotDbManager::new(
                    storage_conf.path_snapshot_dir.clone(),
                    storage_conf.max_open_snapshots,
                    storage_conf.use_isolated_db_for_mpt_table,
                    storage_conf.use_isolated_db_for_mpt_table_height,
                    storage_conf.consensus_param.era_epoch_count,
                    storage_conf.backup_mpt_snapshot,
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
            maybe_db_errors: MaybeDeltaTrieDestroyErrors::new(),
            snapshot_associated_mpts_by_epoch: Default::default(),
            in_progress_snapshotting_tasks: Default::default(),
            in_progress_snapshot_finish_signaler: Arc::new(Mutex::new(
                in_progress_snapshot_finish_signaler,
            )),
            in_progress_snapshotting_joiner: Default::default(),
            current_snapshots: Default::default(),
            snapshot_info_map_by_epoch: RwLock::new(snapshot_info_map),
            last_confirmed_snapshottable_epoch_id: Default::default(),
            storage_conf,
            intermediate_trie_root_merkle: RwLock::new(None),
            persist_state_from_initialization: RwLock::new(None),
        }));

        let storage_manager_arc =
            new_storage_manager_result.as_ref().unwrap().clone();
        *new_storage_manager_result.as_ref().unwrap().in_progress_snapshotting_joiner.lock() =
            Some(thread::Builder::new()
                .name("Background Snapshot Joiner".to_string()).spawn(
            move || {
                for exit_program_or_finished_snapshot in
                    in_progress_snapshot_finish_signal_receiver.iter() {
                    if exit_program_or_finished_snapshot.is_none() {
                        break;
                    }
                    let finished_snapshot = exit_program_or_finished_snapshot.unwrap();
                    if let Some(task) = storage_manager_arc
                        .in_progress_snapshotting_tasks.read().get(&finished_snapshot) {
                        let snapshot_result = task.write().join();
                        if let Some(Err(e)) = snapshot_result {
                            warn!(
                                "Background snapshotting for {:?} failed with {}",
                                finished_snapshot, e);
                        }
                    }
                    storage_manager_arc.in_progress_snapshotting_tasks
                        .write().remove(&finished_snapshot);
                }
                // TODO: handle program exit signal.
            }
        )?);

        new_storage_manager_result
            .as_ref()
            .unwrap()
            .load_persist_state()?;

        new_storage_manager_result
    }

    pub fn find_merkle_root(
        current_snapshots: &Vec<SnapshotInfo>, epoch_id: &EpochId,
    ) -> Option<MerkleHash> {
        current_snapshots
            .iter()
            .find(|i| i.get_snapshot_epoch_id() == epoch_id)
            .map(|i| i.merkle_root.clone())
    }

    pub fn wait_for_snapshot(
        &self, snapshot_epoch_id: &EpochId, try_open: bool,
        open_mpt_snapshot: bool,
    ) -> Result<
        Option<GuardedValue<RwLockReadGuard<Vec<SnapshotInfo>>, SnapshotDb>>,
    > {
        // Make sure that the snapshot info is ready at the same time of the
        // snapshot db. This variable is used for the whole scope
        // however prefixed with _ to please cargo fmt.
        let _snapshot_info_lock = self.snapshot_info_map_by_epoch.read();
        // maintain_snapshots_pivot_chain_confirmed() can not delete snapshot
        // while the current_snapshots are read locked.
        let guard = self.current_snapshots.read();
        match self.snapshot_manager.get_snapshot_by_epoch_id(
            snapshot_epoch_id,
            try_open,
            open_mpt_snapshot,
        )? {
            Some(snapshot_db) => {
                Ok(Some(GuardedValue::new(guard, snapshot_db)))
            }
            None => {
                drop(_snapshot_info_lock);
                drop(guard);
                // Wait for in progress snapshot.
                if let Some(in_progress_snapshot_task) = self
                    .in_progress_snapshotting_tasks
                    .read()
                    .get(snapshot_epoch_id)
                    .cloned()
                {
                    // Snapshotting error is thrown-out when the snapshot is
                    // first requested here.
                    if let Some(result) =
                        in_progress_snapshot_task.write().join()
                    {
                        result?;
                    }
                    let guard = self.current_snapshots.read();
                    match self.snapshot_manager.get_snapshot_by_epoch_id(
                        snapshot_epoch_id,
                        try_open,
                        open_mpt_snapshot,
                    ) {
                        Err(e) => Err(e),
                        Ok(None) => Ok(None),
                        Ok(Some(snapshot_db)) => {
                            Ok(Some(GuardedValue::new(guard, snapshot_db)))
                        }
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn graceful_shutdown(&self) {
        // TODO: First cancel any ongoing thread join from
        // in_progress_snapshotting_joiner thread.
        self.in_progress_snapshot_finish_signaler
            .lock()
            .send(None)
            .ok();
        if let Some(joiner) = self.in_progress_snapshotting_joiner.lock().take()
        {
            joiner.join().ok();
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

    pub fn get_snapshot_info_at_epoch(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<SnapshotInfo> {
        self.snapshot_info_map_by_epoch
            .read()
            .get(snapshot_epoch_id)
            .map(Clone::clone)
    }

    pub fn get_delta_mpt(
        self: &Arc<Self>, snapshot_epoch_id: &EpochId,
    ) -> Result<Arc<DeltaMpt>> {
        {
            let snapshot_associated_mpts_locked =
                self.snapshot_associated_mpts_by_epoch.read();
            match snapshot_associated_mpts_locked.get(snapshot_epoch_id) {
                None => bail!(Error::DeltaMPTEntryNotFound),
                Some(delta_mpts) => {
                    if delta_mpts.1.is_some() {
                        return Ok(delta_mpts.1.as_ref().unwrap().clone());
                    }
                }
            }
        }

        StorageManager::new_or_get_delta_mpt(
            self.clone(),
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
            None => bail!(Error::DeltaMPTEntryNotFound),
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
    ) -> Result<Arc<DeltaMpt>> {
        // Don't hold the lock while doing db io.
        // If the DeltaMpt already exists, the empty delta db creation should
        // fail already.

        let mut maybe_snapshot_entry =
            snapshot_associated_mpts_mut.get_mut(snapshot_epoch_id);
        if maybe_snapshot_entry.is_none() {
            bail!(Error::SnapshotNotFound);
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
            let mpt_id = storage_manager.delta_mpts_id_gen.lock().allocate()?;
            let db_result = storage_manager
                .delta_mpt_open_db_lru
                .create(&snapshot_epoch_id, mpt_id);
            if db_result.is_err() {
                storage_manager.delta_mpts_id_gen.lock().free(mpt_id);
                db_result?;
            }
            let arc_delta_mpt = Arc::new(DeltaMpt::new(
                storage_manager.delta_mpt_open_db_lru.clone(),
                snapshot_epoch_id.clone(),
                storage_manager.clone(),
                mpt_id,
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
        debug!(
            "release_delta_mpt_actions_in_drop: snapshot_epoch_id: {:?}, delta_mpt_id: {}",
            snapshot_epoch_id, delta_mpt_id
        );
        self.delta_mpts_node_memory_manager
            .delete_mpt_from_cache(delta_mpt_id);
        self.delta_mpt_open_db_lru.release(delta_mpt_id, true);
        self.delta_mpts_id_gen.lock().free(delta_mpt_id);
        self.maybe_db_errors.set_maybe_error(
            self.delta_db_manager
                .destroy_delta_db(
                    &self.delta_db_manager.get_delta_db_name(snapshot_epoch_id),
                )
                .err(),
        );
    }

    fn release_delta_mpts_from_snapshot(
        &self,
        snapshot_associated_mpts_by_epoch: &mut HashMap<
            EpochId,
            (Option<Arc<DeltaMpt>>, Option<Arc<DeltaMpt>>),
        >,
        snapshot_epoch_id: &EpochId,
    ) -> Result<()> {
        // Release
        snapshot_associated_mpts_by_epoch.remove(snapshot_epoch_id);
        self.maybe_db_errors.take_result()
    }

    pub fn check_make_register_snapshot_background(
        this: Arc<Self>, snapshot_epoch_id: EpochId, height: u64,
        maybe_delta_db: Option<DeltaMptIterator>,
        recover_mpt_during_construct_pivot_state: bool,
    ) -> Result<()> {
        let this_cloned = this.clone();
        let mut in_progress_snapshotting_tasks =
            this_cloned.in_progress_snapshotting_tasks.write();

        let mut recover_mpt_with_kv_snapshot_exist = false;
        if !in_progress_snapshotting_tasks.contains_key(&snapshot_epoch_id)
            && this
                .snapshot_info_map_by_epoch
                .read()
                .get(&snapshot_epoch_id)
                .map_or(true, |info| {
                    if info.snapshot_info_kept_to_provide_sync
                        == SnapshotKeptToProvideSyncStatus::InfoOnly
                    {
                        true
                    } else {
                        recover_mpt_with_kv_snapshot_exist =
                            recover_mpt_during_construct_pivot_state;
                        recover_mpt_during_construct_pivot_state
                    }
                })
        {
            debug!(
                "start check_make_register_snapshot_background: epoch={:?} height={:?}",
                snapshot_epoch_id, height
            );

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
                    epoch_id = match delta_db.mpt.get_parent_epoch(&epoch_id)? {
                        None => bail!(Error::DbValueError),
                        Some(epoch_id) => epoch_id,
                    };
                    delta_height -= 1;
                    pivot_chain_parts[delta_height] = epoch_id.clone();
                    trace!(
                        "check_make_register_snapshot_background: parent epoch_id={:?}",
                        epoch_id
                    );
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
                snapshot_info_kept_to_provide_sync: Default::default(),
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
            let task_finished_sender_cloned =
                this.in_progress_snapshot_finish_signaler.clone();
            let thread_handle = thread::Builder::new()
                .name("Background Snapshotting".into()).spawn(move || {
                // TODO: add support for cancellation and io throttling.
                let f = || -> Result<()> {
                    let (mut snapshot_info_map_locked, new_snapshot_info) = match maybe_delta_db {
                        None => {
                            in_progress_snapshot_info_cloned.merkle_root = MERKLE_NULL_NODE;
                            (this.snapshot_info_map_by_epoch.write(), in_progress_snapshot_info_cloned)
                        }
                        Some(delta_db) => {
                            this.snapshot_manager
                                .get_snapshot_db_manager()
                                .new_snapshot_by_merging(
                                    &parent_snapshot_epoch_id_cloned,
                                    snapshot_epoch_id.clone(), delta_db,
                                    in_progress_snapshot_info_cloned,
                                    &this.snapshot_info_map_by_epoch,
                                    height,
                                    recover_mpt_with_kv_snapshot_exist)?
                        }
                    };
                    if let Err(e) = this.register_new_snapshot(new_snapshot_info.clone(), &mut snapshot_info_map_locked) {
                        error!(
                            "Failed to register new snapshot {:?} {:?}.",
                            snapshot_epoch_id, new_snapshot_info
                        );
                        bail!(e);
                    }

                    task_finished_sender_cloned.lock().send(Some(snapshot_epoch_id))
                        .or(Err(Error::from(Error::MpscError)))?;
                    drop(snapshot_info_map_locked);

                    let debug_snapshot_checkers =
                        this.storage_conf.debug_snapshot_checker_threads;
                    for snapshot_checker in 0..debug_snapshot_checkers {
                        let begin_range =
                            (256 / debug_snapshot_checkers * snapshot_checker) as u8;
                        let end_range =
                            256 / debug_snapshot_checkers * (snapshot_checker + 1);
                        let end_range_excl = if end_range != 256 {
                            Some(vec![end_range as u8])
                        } else {
                            None
                        };
                        let this = this.clone();
                        thread::Builder::new().name(
                            format!("snapshot checker {} - {}", begin_range, end_range)).spawn(
                            move || -> Result<()> {
                                debug!(
                                    "Start snapshot checker {} of {}",
                                    snapshot_checker, debug_snapshot_checkers);
                                let snapshot_db = this.snapshot_manager
                                    .get_snapshot_by_epoch_id(
                                        &snapshot_epoch_id,
                                        /* try_open = */ false,
                                        true
                                    )?.unwrap();
                                let mut set_keys_iter =
                                    snapshot_db.dumped_delta_kv_set_keys_iterator()?;
                                let mut delete_keys_iter =
                                    snapshot_db.dumped_delta_kv_delete_keys_iterator()?;
                                let previous_snapshot_db = this.snapshot_manager
                                    .get_snapshot_by_epoch_id(
                                        &parent_snapshot_epoch_id_cloned,
                                        /* try_open = */ false,
                                        false
                                    )?.unwrap();
                                let mut previous_set_keys_iter = previous_snapshot_db
                                    .dumped_delta_kv_set_keys_iterator()?;
                                let mut previous_delete_keys_iter =
                                    previous_snapshot_db
                                        .dumped_delta_kv_delete_keys_iterator()?;

                                let mut checker_count = 0;

                                let set_iter = set_keys_iter.iter_range(
                                    &[begin_range],
                                    end_range_excl.as_ref().map(|v| &**v))?
                                    .take();
                                checker_count += check_key_value_load(&snapshot_db, set_iter, /* check_value = */ true)?;

                                let set_iter = previous_set_keys_iter.iter_range(
                                    &[begin_range], end_range_excl.as_ref().map(|v| &**v))?
                                    .take();
                                checker_count += check_key_value_load(&snapshot_db, set_iter, /* check_value = */ false)?;

                                let delete_iter = delete_keys_iter.iter_range(
                                    &[begin_range], end_range_excl.as_ref().map(|v| &**v))?
                                    .take();
                                checker_count += check_key_value_load(&snapshot_db, delete_iter, /* check_value = */ false)?;

                                let delete_iter = previous_delete_keys_iter.iter_range(
                                    &[begin_range], end_range_excl.as_ref().map(|v| &**v))?
                                    .take();
                                checker_count += check_key_value_load(&snapshot_db, delete_iter, /* check_value = */ false)?;

                                debug!(
                                    "Finished: snapshot checker {} of {}, {} keys",
                                    snapshot_checker, debug_snapshot_checkers, checker_count);
                                Ok(())
                            }
                        )?;
                    }

                    Ok(())
                };

                let task_result = f();
                if task_result.is_err() {
                    warn!(
                        "Failed to create snapshot for epoch_id {:?} with error {:?}",
                        snapshot_epoch_id, task_result.as_ref().unwrap_err());
                }

                task_result
            })?;

            in_progress_snapshotting_tasks.insert(
                snapshot_epoch_id,
                Arc::new(RwLock::new(InProgressSnapshotTask {
                    snapshot_info: in_progress_snapshot_info,
                    thread_handle: Some(thread_handle),
                })),
            );
        }

        Ok(())
    }

    /// This function is made public only for testing.
    pub fn register_new_snapshot(
        self: &Arc<Self>, new_snapshot_info: SnapshotInfo,
        snapshot_info_map_locked: &mut PersistedSnapshotInfoMap,
    ) -> Result<()> {
        debug!("register_new_snapshot: info={:?}", new_snapshot_info);
        let snapshot_epoch_id = new_snapshot_info.get_snapshot_epoch_id();
        // Register intermediate MPT for the new snapshot.
        let mut snapshot_associated_mpts_locked =
            self.snapshot_associated_mpts_by_epoch.write();
        let in_recover_mode =
            snapshot_associated_mpts_locked.contains_key(snapshot_epoch_id);

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
                        self.clone(),
                        &new_snapshot_info.parent_snapshot_epoch_id,
                        &mut *snapshot_associated_mpts_locked,
                    )?);
                snapshot_associated_mpts_locked
                    .remove(&new_snapshot_info.parent_snapshot_epoch_id);

                parent_delta_mpt
            }
            Some(parent_snapshot_associated_mpts) => {
                if parent_snapshot_associated_mpts.1.is_none() {
                    debug!("MPT for parent_snapshot_epoch_id is none");
                    Some(StorageManager::new_or_get_delta_mpt(
                        self.clone(),
                        &new_snapshot_info.parent_snapshot_epoch_id,
                        &mut *snapshot_associated_mpts_locked,
                    )?)
                } else {
                    parent_snapshot_associated_mpts.1.clone()
                }
            }
        };
        let delta_mpt = if in_recover_mode {
            snapshot_associated_mpts_locked
                .get_mut(snapshot_epoch_id)
                // This is guaranteed in the in_recover_mode condition above.
                .unwrap()
                .1
                .take()
        } else {
            None
        };
        if !in_recover_mode || maybe_intermediate_delta_mpt.is_some() {
            snapshot_associated_mpts_locked.insert(
                snapshot_epoch_id.clone(),
                (maybe_intermediate_delta_mpt, delta_mpt),
            );
        }

        drop(snapshot_associated_mpts_locked);
        snapshot_info_map_locked
            .insert(snapshot_epoch_id, new_snapshot_info.clone())?;
        if !in_recover_mode {
            self.current_snapshots.write().push(new_snapshot_info);
        }

        Ok(())
    }

    pub fn maintain_state_confirmed<ConsensusInner: StateMaintenanceTrait>(
        &self, consensus_inner: &ConsensusInner, stable_checkpoint_height: u64,
        era_epoch_count: u64, confirmed_height: u64,
        state_availability_boundary: &RwLock<StateAvailabilityBoundary>,
    ) -> Result<()> {
        let additional_state_height_gap =
            (self.storage_conf.additional_maintained_snapshot_count
                * self.get_snapshot_epoch_count()) as u64;
        let maintained_state_height_lower_bound =
            if confirmed_height > additional_state_height_gap {
                confirmed_height - additional_state_height_gap
            } else {
                0
            };
        if maintained_state_height_lower_bound
            <= state_availability_boundary.read().lower_bound
        {
            return Ok(());
        }
        let maintained_epoch_id = consensus_inner
            .get_pivot_hash_from_epoch_number(
                maintained_state_height_lower_bound,
            )?;
        let maintained_epoch_execution_commitment = consensus_inner
            .get_epoch_execution_commitment_with_db(&maintained_epoch_id);
        let maintained_state_root = match &maintained_epoch_execution_commitment
        {
            Some(commitment) => &commitment.state_root_with_aux_info,
            None => return Ok(()),
        };

        self.maintain_snapshots_pivot_chain_confirmed(
            maintained_state_height_lower_bound,
            &maintained_epoch_id,
            maintained_state_root,
            state_availability_boundary,
            &|height, find_nearest_snapshot_multiple_of| {
                extra_snapshots_to_keep_predicate(
                    &self.storage_conf,
                    stable_checkpoint_height,
                    era_epoch_count,
                    height,
                    find_nearest_snapshot_multiple_of,
                )
            },
            stable_checkpoint_height,
        )
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
        &self, maintained_state_height_lower_bound: u64,
        maintained_epoch_id: &EpochId,
        maintained_state_root: &StateRootWithAuxInfo,
        state_availability_boundary: &RwLock<StateAvailabilityBoundary>,
        extra_snapshots_to_keep: &dyn Fn(u64, &mut bool) -> bool,
        stable_checkpoint_height: u64,
    ) -> Result<()> {
        // Update the confirmed epoch id. Skip remaining actions when the
        // confirmed snapshot-able epoch id doesn't change
        {
            let mut last_confirmed_snapshottable_id_locked =
                self.last_confirmed_snapshottable_epoch_id.lock();
            if last_confirmed_snapshottable_id_locked.is_some() {
                if maintained_state_root.aux_info.intermediate_epoch_id.eq(
                    last_confirmed_snapshottable_id_locked.as_ref().unwrap(),
                ) {
                    return Ok(());
                }
            }
            *last_confirmed_snapshottable_id_locked = Some(
                maintained_state_root.aux_info.intermediate_epoch_id.clone(),
            );
        }

        let confirmed_intermediate_height = maintained_state_height_lower_bound
            - StateIndex::height_to_delta_height(
                maintained_state_height_lower_bound,
                self.get_snapshot_epoch_count(),
            ) as u64;

        let confirmed_snapshot_height = if confirmed_intermediate_height
            > self.get_snapshot_epoch_count() as u64
        {
            confirmed_intermediate_height
                - self.get_snapshot_epoch_count() as u64
        } else {
            0
        };
        let first_available_state_height = if confirmed_snapshot_height > 0 {
            confirmed_snapshot_height + 1
        } else {
            0
        };

        debug!(
            "maintain_snapshots_pivot_chain_confirmed: confirmed_height {}, \
             confirmed_epoch_id {:?}, confirmed_intermediate_id {:?}, \
             confirmed_snapshot_id {:?}, confirmed_intermediate_height {}, \
             confirmed_snapshot_height {}, first_available_state_height {}",
            maintained_state_height_lower_bound,
            maintained_epoch_id,
            maintained_state_root.aux_info.intermediate_epoch_id,
            maintained_state_root.aux_info.snapshot_epoch_id,
            confirmed_intermediate_height,
            confirmed_snapshot_height,
            first_available_state_height,
        );
        let mut extra_snapshot_infos_kept_for_sync = vec![];
        let mut non_pivot_snapshots_to_remove = HashSet::new();
        let mut old_pivot_snapshots_to_remove = vec![];
        // We will keep some extra snapshots to provide sync. For any snapshot
        // to keep, we must keep all snapshot_info from the pivot tip to
        // the snapshot, so that in the next run the snapshot is still
        // recognized as "old pivot".
        let mut old_pivot_snapshot_infos_to_remove = vec![];
        let mut find_nearest_multiple_of = false;
        let mut in_progress_snapshot_to_cancel = vec![];

        {
            let current_snapshots = self.current_snapshots.read();

            let mut prev_snapshot_epoch_id = &NULL_EPOCH;

            // Check snapshots which has height lower than confirmed_height
            for snapshot_info in current_snapshots.iter().rev() {
                let snapshot_epoch_id = snapshot_info.get_snapshot_epoch_id();
                if snapshot_info.height == confirmed_snapshot_height {
                    // Remove all non-pivot Snapshot at
                    // confirmed_snapshot_height
                    if snapshot_epoch_id
                        .eq(&maintained_state_root.aux_info.snapshot_epoch_id)
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
                        if extra_snapshots_to_keep(
                            snapshot_info.height,
                            &mut find_nearest_multiple_of,
                        ) {
                            // For any snapshot to keep, we keep all snapshot
                            // infos from pivot tip to it.
                            for snapshot_epoch_id_to_keep_info in std::mem::take(
                                &mut old_pivot_snapshot_infos_to_remove,
                            ) {
                                extra_snapshot_infos_kept_for_sync.push((
                                    snapshot_epoch_id_to_keep_info,
                                    SnapshotKeptToProvideSyncStatus::InfoOnly,
                                ));
                            }
                            extra_snapshot_infos_kept_for_sync
                                .push((snapshot_epoch_id.clone(), SnapshotKeptToProvideSyncStatus::InfoAndSnapshot));
                        } else {
                            // Retain the snapshot information for the one
                            // preceding the stable checkpoint
                            if snapshot_info.height
                                + self
                                    .storage_conf
                                    .consensus_param
                                    .snapshot_epoch_count
                                    as u64
                                != stable_checkpoint_height
                            {
                                old_pivot_snapshot_infos_to_remove
                                    .push(snapshot_epoch_id.clone());
                            }
                            old_pivot_snapshots_to_remove
                                .push(snapshot_epoch_id.clone());
                        }
                        prev_snapshot_epoch_id =
                            &snapshot_info.parent_snapshot_epoch_id;
                    } else {
                        // Any other snapshot with higher height is non-pivot.
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_epoch_id.clone());
                    }
                } else if snapshot_info.height
                    < maintained_state_height_lower_bound
                {
                    // There can be at most 1 snapshot between the snapshot at
                    // confirmed_snapshot_height and confirmed_height.
                    //
                    // When a snapshot has height > confirmed_snapshot_height,
                    // but doesn't contain confirmed_state_root.aux_info.
                    // intermediate_epoch_id, it must be a non-pivot fork.
                    if snapshot_info
                        .get_epoch_id_at_height(confirmed_intermediate_height)
                        != Some(
                            &maintained_state_root
                                .aux_info
                                .intermediate_epoch_id,
                        )
                    {
                        debug!(
                            "remove mismatch intermediate snapshot: {:?}",
                            snapshot_info.get_epoch_id_at_height(
                                confirmed_intermediate_height
                            )
                        );
                        non_pivot_snapshots_to_remove
                            .insert(snapshot_epoch_id.clone());
                    }
                }
            }

            debug!(
                "finished scanning for lower snapshots: \
                 old_pivot_snapshots_to_remove {:?}, \
                 old_pivot_snapshot_infos_to_remove {:?}, \
                 non_pivot_snapshots_to_remove {:?}",
                old_pivot_snapshots_to_remove,
                old_pivot_snapshot_infos_to_remove,
                non_pivot_snapshots_to_remove
            );

            // Check snapshots which has height >= confirmed_height
            for snapshot_info in &*current_snapshots {
                // Check for non-pivot snapshot to remove.
                match snapshot_info
                    .get_epoch_id_at_height(maintained_state_height_lower_bound)
                {
                    Some(path_epoch_id) => {
                        // Check if the snapshot is within
                        // confirmed_epoch's
                        // subtree.
                        if path_epoch_id != maintained_epoch_id {
                            debug!(
                                "remove non-subtree snapshot {:?}, got {:?}, expected {:?}",
                                snapshot_info.get_snapshot_epoch_id(),
                                path_epoch_id, maintained_epoch_id,
                            );
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
                            debug!(
                                "remove non-subtree deep snapshot {:?}, parent_snapshot_epoch_id {:?}",
                                snapshot_info.get_snapshot_epoch_id(),
                                snapshot_info.parent_snapshot_epoch_id
                            );
                            // The snapshot may already exist. This is why we
                            // must use HashSet for
                            // non_pivot_snapshots_to_remove.
                            non_pivot_snapshots_to_remove.insert(
                                snapshot_info.get_snapshot_epoch_id().clone(),
                            );
                        }
                    }
                }
            }
        }

        for (in_progress_epoch_id, in_progress_snapshot_task) in
            &*self.in_progress_snapshotting_tasks.read()
        {
            let mut to_cancel = false;
            let in_progress_snapshot_info =
                &in_progress_snapshot_task.read().snapshot_info;

            // The logic is similar as above for snapshot deletion.
            if in_progress_snapshot_info.height < confirmed_intermediate_height
            {
                to_cancel = true;
            } else if in_progress_snapshot_info.height
                < maintained_state_height_lower_bound
            {
                if in_progress_snapshot_info
                    .get_epoch_id_at_height(confirmed_intermediate_height)
                    != Some(
                        &maintained_state_root.aux_info.intermediate_epoch_id,
                    )
                {
                    to_cancel = true;
                }
            } else {
                match in_progress_snapshot_info
                    .get_epoch_id_at_height(maintained_state_height_lower_bound)
                {
                    Some(path_epoch_id) => {
                        if path_epoch_id != maintained_epoch_id {
                            to_cancel = true;
                        }
                    }
                    None => {
                        if non_pivot_snapshots_to_remove.contains(
                            &in_progress_snapshot_info.parent_snapshot_epoch_id,
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

        let mut non_pivot_snapshots_to_remove =
            non_pivot_snapshots_to_remove.drain().collect();
        // Update snapshot_infos and filter out already removed snapshots from
        // the removal lists.
        {
            let mut info_maps = self.snapshot_info_map_by_epoch.write();
            let removal_filter = |vec: &mut Vec<EpochId>| {
                vec.retain(|epoch| {
                    info_maps.get(epoch).map_or(true, |info| {
                        // The snapshot itself is already removed.
                        info.snapshot_info_kept_to_provide_sync
                            != SnapshotKeptToProvideSyncStatus::InfoOnly
                    })
                })
            };
            removal_filter(&mut non_pivot_snapshots_to_remove);
            removal_filter(&mut old_pivot_snapshots_to_remove);

            let mut updated_snapshot_info_epochs =
                HashMap::<EpochId, SnapshotKeptToProvideSyncStatus>::default();
            for (epoch, new_status) in &extra_snapshot_infos_kept_for_sync {
                if let Some(info) = info_maps.get(epoch) {
                    if info.snapshot_info_kept_to_provide_sync != *new_status {
                        let mut new_snapshot_info = info.clone();
                        new_snapshot_info.snapshot_info_kept_to_provide_sync =
                            *new_status;
                        info_maps.insert(epoch, new_snapshot_info)?;
                        updated_snapshot_info_epochs
                            .insert(*epoch, *new_status);
                    }
                }
            }
            if updated_snapshot_info_epochs.len() > 0 {
                let mut current_snapshots = self.current_snapshots.write();
                for snapshot_info in current_snapshots.iter_mut() {
                    if let Some(new_status) = updated_snapshot_info_epochs
                        .get(&snapshot_info.get_snapshot_epoch_id())
                    {
                        snapshot_info.snapshot_info_kept_to_provide_sync =
                            *new_status;
                    }
                }
            }
        }
        if !non_pivot_snapshots_to_remove.is_empty()
            || !old_pivot_snapshots_to_remove.is_empty()
        {
            {
                // TODO: Archive node may do something different.
                let state_boundary = &mut *state_availability_boundary.write();
                if first_available_state_height > state_boundary.lower_bound {
                    state_boundary
                        .adjust_lower_bound(first_available_state_height);
                }
            }

            self.remove_snapshots(
                &old_pivot_snapshots_to_remove,
                &non_pivot_snapshots_to_remove,
                &old_pivot_snapshot_infos_to_remove
                    .iter()
                    .chain(non_pivot_snapshots_to_remove.iter())
                    .cloned()
                    .collect(),
            )?;
        }

        // TODO: implement in_progress_snapshot cancellation.
        /*
        if !in_progress_snapshot_to_cancel.is_empty() {
            let mut in_progress_snapshotting_locked =
                self.in_progress_snapshotting_tasks.write();
            for epoch_id in in_progress_snapshot_to_cancel {
                unimplemented!();
            }
        }
        */

        info!("maintain_snapshots_pivot_chain_confirmed: finished");
        Ok(())
    }

    fn remove_snapshots(
        &self, old_pivot_snapshots_to_remove: &[EpochId],
        non_pivot_snapshots_to_remove: &[EpochId],
        snapshot_infos_to_remove: &HashSet<EpochId>,
    ) -> Result<()> {
        let mut current_snapshots_locked = self.current_snapshots.write();
        current_snapshots_locked.retain(|x| {
            !snapshot_infos_to_remove.contains(x.get_snapshot_epoch_id())
        });
        info!(
            "maintain_snapshots_pivot_chain_confirmed: remove the following snapshot infos {:?}",
            snapshot_infos_to_remove,
        );
        for snapshot_epoch_id in old_pivot_snapshots_to_remove {
            self.snapshot_manager
                .remove_old_pivot_snapshot(&snapshot_epoch_id)?;
        }
        for snapshot_epoch_id in non_pivot_snapshots_to_remove {
            self.snapshot_manager
                .remove_non_pivot_snapshot(&snapshot_epoch_id)?;
        }

        drop(current_snapshots_locked);
        unsafe {
            let mut snapshot_info_map = self.snapshot_info_map_by_epoch.write();
            for snapshot_epoch_id in snapshot_infos_to_remove {
                snapshot_info_map.remove_in_mem_only(snapshot_epoch_id);
            }
        }
        {
            let snapshot_associated_mpts_by_epoch_locked =
                &mut *self.snapshot_associated_mpts_by_epoch.write();

            for snapshot_epoch_id in old_pivot_snapshots_to_remove
                .iter()
                .chain(non_pivot_snapshots_to_remove.iter())
            {
                self.release_delta_mpts_from_snapshot(
                    snapshot_associated_mpts_by_epoch_locked,
                    snapshot_epoch_id,
                )?
            }
        }
        {
            // Only remove snapshot_info from db when no exception have
            // happened.
            let mut snapshot_info_map_by_epoch =
                self.snapshot_info_map_by_epoch.write();
            for snapshot_epoch_id in snapshot_infos_to_remove {
                snapshot_info_map_by_epoch.remove(&snapshot_epoch_id)?;
            }
        }

        Ok(())
    }

    pub fn log_usage(&self) {
        let mut delta_mpts = HashMap::new();
        for (_snapshot_epoch_id, associated_delta_mpts) in
            &*self.snapshot_associated_mpts_by_epoch.read()
        {
            if let Some(delta_mpt) = associated_delta_mpts.0.as_ref() {
                delta_mpts.insert(delta_mpt.get_mpt_id(), delta_mpt.clone());
            }
            if let Some(delta_mpt) = associated_delta_mpts.1.as_ref() {
                delta_mpts.insert(delta_mpt.get_mpt_id(), delta_mpt.clone());
            }
        }
        if let Some((_mpt_id, delta_mpt)) = delta_mpts.iter().next() {
            delta_mpt.log_usage();

            // Now delta_mpt calls log_usage of the singleton
            // node_memory_manager, so there is no need to log_usage
            // on second delta_mpt.
        }
    }

    pub fn load_persist_state(self: &Arc<Self>) -> Result<()> {
        let snapshot_info_map = &mut *self.snapshot_info_map_by_epoch.write();

        // Always keep the information for genesis snapshot.
        self.snapshot_associated_mpts_by_epoch
            .write()
            .insert(NULL_EPOCH, (None, None));
        snapshot_info_map
            .insert(&NULL_EPOCH, SnapshotInfo::genesis_snapshot_info())?;
        self.current_snapshots
            .write()
            .push(SnapshotInfo::genesis_snapshot_info());

        // Persist state loaded.
        let snapshot_persist_state = self
            .snapshot_manager
            .get_snapshot_db_manager()
            .scan_persist_state(snapshot_info_map.get_map())?;

        debug!("snapshot persist state {:?}", snapshot_persist_state);

        *self.persist_state_from_initialization.write() = Some((
            snapshot_persist_state.temp_snapshot_db_existing,
            snapshot_persist_state.removed_snapshots,
            snapshot_persist_state.max_epoch_height,
            snapshot_persist_state.max_snapshot_epoch_height_has_mpt,
        ));
        self.snapshot_manager
            .get_snapshot_db_manager()
            .update_latest_snapshot_id(
                snapshot_persist_state.max_epoch_id,
                snapshot_persist_state.max_epoch_height,
            );

        // Remove missing snapshots.
        for snapshot_epoch_id in snapshot_persist_state.missing_snapshots {
            if snapshot_epoch_id == NULL_EPOCH {
                continue;
            }
            // Remove the delta mpt if the snapshot is missing.
            self.delta_db_manager
                .destroy_delta_db(
                    &self
                        .delta_db_manager
                        .get_delta_db_name(&snapshot_epoch_id),
                )
                .or_else(|e| match &e {
                    Error::Io(io_err) => match io_err.kind() {
                        std::io::ErrorKind::NotFound => Ok(()),
                        _ => Err(e),
                    },
                    _ => Err(e),
                })?;
            snapshot_info_map.remove(&snapshot_epoch_id)?;
        }

        let (missing_delta_db_snapshots, delta_dbs) = self
            .delta_db_manager
            .scan_persist_state(snapshot_info_map.get_map())?;

        let mut delta_mpts = HashMap::new();
        for (snapshot_epoch_id, delta_db) in delta_dbs {
            let mpt_id = self.delta_mpts_id_gen.lock().allocate()?;
            self.delta_mpt_open_db_lru.import(
                &snapshot_epoch_id,
                mpt_id,
                delta_db,
            )?;
            delta_mpts.insert(
                snapshot_epoch_id.clone(),
                Arc::new(DeltaMpt::new(
                    self.delta_mpt_open_db_lru.clone(),
                    snapshot_epoch_id.clone(),
                    self.clone(),
                    mpt_id,
                    self.delta_mpts_node_memory_manager.clone(),
                )?),
            );
        }

        for snapshot_epoch_id in missing_delta_db_snapshots {
            if snapshot_epoch_id == NULL_EPOCH {
                continue;
            }
            // Do not remove a snapshot which has intermediate delta mpt,
            // because it could be a freshly made snapshot before the previous
            // shutdown. A freshly made snapshot does not have delta db yet.
            if let Some(snapshot_info) =
                snapshot_info_map.get(&snapshot_epoch_id)
            {
                if delta_mpts
                    .contains_key(&snapshot_info.parent_snapshot_epoch_id)
                {
                    continue;
                }
            }
            error!(
                "Missing intermediate mpt and delta mpt for snapshot {:?}",
                snapshot_epoch_id
            );
            snapshot_info_map.remove(&snapshot_epoch_id)?;
            self.snapshot_manager
                .get_snapshot_db_manager()
                .destroy_snapshot(&snapshot_epoch_id)?;
        }

        // Restore current_snapshots.
        let mut snapshots = snapshot_info_map
            .get_map()
            .iter()
            .map(|(_, snapshot_info)| snapshot_info.clone())
            .collect::<Vec<_>>();
        snapshots.sort_by(|x, y| x.height.partial_cmp(&y.height).unwrap());

        let current_snapshots = &mut *self.current_snapshots.write();
        *current_snapshots = snapshots;

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

        Ok(())
    }
}

fn extra_snapshots_to_keep_predicate(
    storage_conf: &StorageConfiguration, stable_checkpoint_height: u64,
    era_epoch_count: u64, height: u64,
    find_epoch_nearest_multiple_of: &mut bool,
) -> bool {
    for conf in &storage_conf.provide_more_snapshot_for_sync {
        match conf {
            ProvideExtraSnapshotSyncConfig::StableCheckpoint => {
                if height >= stable_checkpoint_height
                    && (height - stable_checkpoint_height) % era_epoch_count
                        == 0
                {
                    return true;
                }
                // The bound_height ensures that the snapshot before
                // stable_genesis will not be removed, so that
                // the execution of the epochs following
                // stable_genesis can go through a normal path where both
                // snapshot and intermediate delta mpt exist.
                // TODO:
                //  this is a corner case which should be addressed, so that we
                //  can don't really need the snapshot prior to the checkpoint.
                let check_next_snapshot_height = height
                    + (storage_conf.consensus_param.snapshot_epoch_count
                        as u64);
                if (check_next_snapshot_height >= stable_checkpoint_height)
                    && (check_next_snapshot_height - stable_checkpoint_height)
                        % era_epoch_count
                        == 0
                {
                    return storage_conf.keep_snapshot_before_stable_checkpoint;
                }

                if storage_conf.keep_era_genesis_snapshot {
                    let era_genesis_snapshot_height =
                        if stable_checkpoint_height
                            >= storage_conf.consensus_param.era_epoch_count
                        {
                            stable_checkpoint_height
                                - storage_conf.consensus_param.era_epoch_count
                        } else {
                            0
                        };

                    if era_genesis_snapshot_height == height {
                        return true;
                    }
                }
            }
            ProvideExtraSnapshotSyncConfig::EpochNearestMultipleOf(
                multiple,
            ) => {
                if *find_epoch_nearest_multiple_of
                    && height % (*multiple as u64) == 0
                {
                    *find_epoch_nearest_multiple_of = false;
                    return true;
                }
            }
        }
    }
    false
}

struct MaybeDeltaTrieDestroyErrors {
    delta_trie_destroy_error_1: Cell<Option<Error>>,
    delta_trie_destroy_error_2: Cell<Option<Error>>,
}

// It's only used when relevant lock has been acquired.
unsafe impl Sync for MaybeDeltaTrieDestroyErrors {}

impl MaybeDeltaTrieDestroyErrors {
    fn new() -> Self {
        Self {
            delta_trie_destroy_error_1: Cell::new(None),
            delta_trie_destroy_error_2: Cell::new(None),
        }
    }

    fn set_maybe_error(&self, e: Option<Error>) {
        self.delta_trie_destroy_error_2
            .replace(self.delta_trie_destroy_error_1.replace(e));
    }

    fn take_result(&self) -> Result<()> {
        let e1 = self.delta_trie_destroy_error_1.take().map(|e| Box::new(e));
        let e2 = self.delta_trie_destroy_error_2.take().map(|e| Box::new(e));
        if e1.is_some() || e2.is_some() {
            Err(Error::DeltaMPTDestroyErrors { e1, e2 }.into())
        } else {
            Ok(())
        }
    }
}

lazy_static! {
    static ref SNAPSHOT_KVDB_STATEMENTS: Arc<KvdbSqliteStatements> = Arc::new(
        KvdbSqliteStatements::make_statements(
            &["value"],
            &["BLOB"],
            &storage_dir::SNAPSHOT_INFO_DB_NAME,
            false
        )
        .unwrap()
    );
}

use crate::{
    impls::{
        delta_mpt::{
            node_memory_manager::{
                DeltaMptsCacheAlgorithm, DeltaMptsNodeMemoryManager,
            },
            node_ref_map::DeltaMptId,
        },
        errors::*,
        state_manager::{DeltaDbManager, SnapshotDb, SnapshotDbManager},
        storage_db::{
            kvdb_sqlite::{
                kvdb_sqlite_iter_range_impl, KvdbSqliteDestructureTrait,
                KvdbSqliteStatements,
            },
            snapshot_kv_db_sqlite::test_lib::check_key_value_load,
        },
        storage_manager::snapshot_manager::SnapshotManager,
    },
    snapshot_manager::SnapshotManagerTrait,
    storage_db::{
        DeltaDbManagerTrait, KeyValueDbIterableTrait, SnapshotDbManagerTrait,
        SnapshotInfo, SnapshotKeptToProvideSyncStatus,
    },
    storage_dir,
    utils::guarded_value::GuardedValue,
    DeltaMpt, DeltaMptIdGen, DeltaMptIterator, KeyValueDbTrait, KvdbSqlite,
    OpenDeltaDbLru, ProvideExtraSnapshotSyncConfig, StateIndex,
    StateRootWithAuxInfo, StorageConfiguration,
};
use cfx_internal_common::{
    consensus_api::StateMaintenanceTrait, StateAvailabilityBoundary,
};
use fallible_iterator::FallibleIterator;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use rlp::{Decodable, DecoderError, Encodable, Rlp};
use sqlite::Statement;
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    fs,
    sync::{
        mpsc::{channel, Sender},
        Arc, Weak,
    },
    thread::{self, JoinHandle},
};
