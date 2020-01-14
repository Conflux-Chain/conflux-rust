// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type ActualSlabIndex = u32;

pub type VacantEntry<'a, TrieNode> =
    super::slab::VacantEntry<'a, TrieNode, TrieNode>;

// We use UnsafeCell in Slab because we hold references and mutable references
// of Slab entries independently.
pub type TrieNodeCell<CacheAlgoDataT> =
    UnsafeCell<MemOptimizedTrieNode<CacheAlgoDataT>>;
type Allocator<CacheAlgoDataT> =
    Slab<TrieNodeCell<CacheAlgoDataT>, TrieNodeCell<CacheAlgoDataT>>;
pub type AllocatorRef<'a, CacheAlgoDataT> =
    RwLockReadGuard<'a, Allocator<CacheAlgoDataT>>;
pub type AllocatorRefRef<'a, CacheAlgoDataT> =
    &'a AllocatorRef<'a, CacheAlgoDataT>;

pub type RLFUPosT = u32;
pub type DeltaMptsCacheAlgorithm = LRU<RLFUPosT, (DeltaMptId, DeltaMptDbKey)>;
pub type DeltaMptsCacheAlgoData =
    <DeltaMptsCacheAlgorithm as CacheAlgorithm>::CacheAlgoData;

pub type TrieNodeDeltaMpt = MemOptimizedTrieNode<DeltaMptsCacheAlgoData>;
pub type TrieNodeDeltaMptCell = TrieNodeCell<DeltaMptsCacheAlgoData>;

pub type SlabVacantEntryDeltaMpt<'a> = VacantEntry<'a, TrieNodeDeltaMptCell>;
pub type AllocatorRefRefDeltaMpt<'a> =
    &'a AllocatorRef<'a, DeltaMptsCacheAlgoData>;

pub type DeltaMptsNodeMemoryManager =
    NodeMemoryManager<DeltaMptsCacheAlgoData, DeltaMptsCacheAlgorithm>;
pub type DeltaMptsCacheManager =
    CacheManagerDeltaMpts<DeltaMptsCacheAlgoData, DeltaMptsCacheAlgorithm>;

impl CacheIndexTrait for DeltaMptDbKey {}

pub struct NodeMemoryManager<
    CacheAlgoDataT: CacheAlgoDataTrait,
    CacheAlgorithmT: CacheAlgorithm<CacheAlgoData = CacheAlgoDataT>,
> {
    /// The max number of nodes.
    size_limit: u32,
    /// Unless size limit reached, there should be at lease idle_size available
    /// after each resize.
    idle_size: u32,
    /// Always get the read lock for allocator first because resizing requires
    /// write lock and it could be very slow, which we don't want to wait
    /// for inside critical section.
    allocator: RwLock<Allocator<CacheAlgoDataT>>,
    /// Cache space is shared for all Delta MPTs.
    cache: Mutex<CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>>,
    /// To prevent multiple db load to happen for the same key, and make sure
    /// that the get is always successful when exiting the critical
    /// section.
    db_load_lock: Mutex<()>,

    // FIXME use other atomic integer types as they are in rust stable.
    db_load_counter: AtomicUsize,
    uncached_leaf_load_times: AtomicUsize,
    uncached_leaf_db_loads: AtomicUsize,
    pub compute_merkle_db_loads: AtomicUsize,
    children_merkle_db_loads: AtomicUsize,
}

impl<
        CacheAlgoDataT: CacheAlgoDataTrait,
        CacheAlgorithmT: CacheAlgorithm<CacheAlgoData = CacheAlgoDataT>,
    > NodeMemoryManager<CacheAlgoDataT, CacheAlgorithmT>
{
    /// In disk hybrid solution, the nodes in memory are merely LRU cache of
    /// non-leaf nodes. So the memory consumption is (192B Trie + 10B R_LFU +
    /// 12B*4x LRU) * number of nodes + 200M * 4B NodeRef. 5GB + extra 800M
    /// ~ 20_000_000 nodes.
    // TODO(yz): Need to calculate a factor in LRU (currently made up to 4).
    pub const MAX_CACHED_TRIE_NODES_DISK_HYBRID: u32 = 20_000_000;
    pub const MAX_CACHED_TRIE_NODES_R_LFU_COUNTER: u32 = (Self::R_LFU_FACTOR
        * Self::MAX_CACHED_TRIE_NODES_DISK_HYBRID as f64)
        as u32;
    /// Splitting out dirty trie nodes may remove the hard limit, however it
    /// introduces copies for committing.
    // TODO(yz): log the dirty size to monitor if other component produces too
    // many.
    pub const MAX_DIRTY_AND_TEMPORARY_TRIE_NODES: u32 = 200_000;
    /// If we do not swap out any node onto disk, the maximum tolerable nodes is
    /// about 27.6M, where there is about 4.6M leaf nodes. The total memory
    /// consumption is about (27.6 * 192 - 4.6 * 64) MB ~= 5GB. It can hold new
    /// items for about 38 min assuming 2k updates per second.
    /// The reason of having much more nodes than leaf nodes is that this is a
    /// multiple version tree, so we have a factor of 3.3 (extra layers) per
    /// leaf node. This assumption is for delta_trie.
    pub const MAX_TRIE_NODES_MEM_ONLY: u32 = 27_600_000;
    pub const R_LFU_FACTOR: f64 = 4.0;
    pub const START_CAPACITY: u32 = 1_000_000;
}

impl<
        CacheAlgoDataT: CacheAlgoDataTrait,
        CacheAlgorithmT: CacheAlgorithm<
            CacheAlgoData = CacheAlgoDataT,
            CacheIndex = (DeltaMptId, DeltaMptDbKey),
        >,
    > NodeMemoryManager<CacheAlgoDataT, CacheAlgorithmT>
{
    pub fn new(
        cache_start_size: u32, cache_size: u32, idle_size: u32,
        _node_ref_map_vec_size: u32, cache_algorithm: CacheAlgorithmT,
    ) -> Self
    {
        let size_limit = cache_size + idle_size;
        Self {
            size_limit,
            idle_size,
            allocator: RwLock::new(
                Slab::with_capacity((cache_start_size + idle_size) as usize)
                    .into(),
            ),
            cache: Mutex::new(CacheManagerDeltaMpts {
                node_ref_map: NodeRefMapDeltaMpts::new(),
                cache_algorithm,
            }),
            db_load_lock: Default::default(),
            db_load_counter: Default::default(),
            uncached_leaf_db_loads: Default::default(),
            uncached_leaf_load_times: Default::default(),
            compute_merkle_db_loads: Default::default(),
            children_merkle_db_loads: Default::default(),
        }
    }

    pub fn get_allocator(&self) -> AllocatorRef<CacheAlgoDataT> {
        self.allocator.read_recursive()
    }

    pub fn get_cache_manager(
        &self,
    ) -> &Mutex<CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>> {
        &self.cache
    }

    /// Method that requires mut borrow of allocator.
    pub fn enlarge(&self) -> Result<()> {
        let mut allocator_mut = self.allocator.write();
        let idle = allocator_mut.capacity() - allocator_mut.len();
        let should_idle = self.idle_size as usize;
        if idle >= should_idle {
            return Ok(());
        }
        let mut add_size = should_idle - idle;
        if add_size < allocator_mut.capacity() {
            add_size = allocator_mut.capacity();
        }
        let max_add_size = self.size_limit as usize - allocator_mut.len();
        if add_size >= max_add_size {
            add_size = max_add_size;
        }
        allocator_mut.reserve_exact(add_size)?;
        Ok(())
    }

    pub fn delete_mpt_from_cache(&self, mpt_id: DeltaMptId) {
        let cache_mut = &mut *self.cache.lock();
        let cache_infos =
            cache_mut.node_ref_map.get_all_cache_infos_from_mpt(mpt_id);
        for (db_key, cache_info) in cache_infos {
            self.delete_from_cache(
                &mut cache_mut.cache_algorithm,
                &mut cache_mut.node_ref_map,
                (mpt_id, db_key),
                cache_info,
            );
            cache_mut.node_ref_map.delete((mpt_id, db_key));
        }
    }

    pub fn log_uncached_key_access(&self, db_load_count: i32) {
        if db_load_count != 0 {
            self.uncached_leaf_db_loads
                .fetch_add(db_load_count as usize, Ordering::Relaxed);
            self.uncached_leaf_load_times
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub unsafe fn get_in_memory_cell<'a>(
        allocator: AllocatorRefRef<'a, CacheAlgoDataT>, cache_slot: usize,
    ) -> &'a TrieNodeCell<CacheAlgoDataT> {
        allocator.get_unchecked(cache_slot)
    }

    pub unsafe fn get_in_memory_node_mut<'a>(
        allocator: AllocatorRefRef<'a, CacheAlgoDataT>, cache_slot: usize,
    ) -> &'a mut MemOptimizedTrieNode<CacheAlgoDataT> {
        allocator.get_unchecked(cache_slot).get_as_mut()
    }

    fn load_from_db<'c: 'a, 'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        cache_manager: &'c Mutex<
            CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        >,
        db: &mut DeltaDbOwnedReadTraitObj, mpt_id: DeltaMptId,
        db_key: DeltaMptDbKey,
    ) -> Result<
        GuardedValue<
            MutexGuard<
                'c,
                CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
            >,
            &'a TrieNodeCell<CacheAlgoDataT>,
        >,
    >
    {
        self.db_load_counter.fetch_add(1, Ordering::Relaxed);
        // We never save null node in db.
        let rlp_bytes = db.get_mut_with_number_key(db_key.into())?.unwrap();
        let rlp = Rlp::new(rlp_bytes.as_ref());
        let mut trie_node = MemOptimizedTrieNode::decode(&rlp)?;

        let mut cache_manager_locked = cache_manager.lock();
        let trie_cell_ref: &TrieNodeCell<CacheAlgoDataT>;

        let cache_mut = &mut *cache_manager_locked;

        // If cache_algo_data exists in node_ref_map, move to trie node.
        match cache_mut.node_ref_map.get_cache_info((mpt_id, db_key)) {
            None => {}
            Some(cache_info) => match cache_info.get_cache_info() {
                TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(_cache_slot) => unsafe {
                    // This should not happen.
                    unreachable_unchecked();
                },
                TrieCacheSlotOrCacheAlgoData::CacheAlgoData(
                    cache_algo_data,
                ) => {
                    trie_node.cache_algo_data = *cache_algo_data;
                }
            },
        }
        // Insert into slab as temporary, then insert into node_ref_map.
        let slot = allocator.insert(&trie_node)?;
        trie_cell_ref = unsafe { allocator.get_unchecked(slot) };
        let cache_insertion_result = cache_mut
            .node_ref_map
            .insert((mpt_id, db_key), slot as ActualSlabIndex);
        if cache_insertion_result.is_err() {
            allocator.remove(slot)?;

            // Throw the insertion error.
            cache_insertion_result?;
        }

        Ok(GuardedValue::new(cache_manager_locked, trie_cell_ref))
    }

    pub fn load_children_merkles_from_db(
        &self, db: &mut DeltaDbOwnedReadTraitObj, db_key: DeltaMptDbKey,
    ) -> Result<Option<CompactedChildrenTable<MerkleHash>>> {
        self.children_merkle_db_loads
            .fetch_add(1, Ordering::Relaxed);
        // cm stands for children merkles, abbreviated to save space
        let rlp_bytes = match db.get_mut(format!("cm{}", db_key).as_bytes())? {
            None => return Ok(None),
            Some(rlp_bytes) => rlp_bytes,
        };
        let rlp = Rlp::new(rlp_bytes.as_ref());
        let table = CompactedChildrenTable::from(
            ChildrenTable::<MerkleHash>::decode(&rlp)?,
        );
        Ok(Some(table))
    }

    fn delete_from_cache(
        &self, cache_algorithm: &mut CacheAlgorithmT,
        node_ref_map: &mut NodeRefMapDeltaMpts<CacheAlgoDataT>,
        cache_index: CacheAlgorithmT::CacheIndex,
        cache_info: CacheableNodeRefDeltaMpt<CacheAlgoDataT>,
    )
    {
        cache_algorithm
            .delete(cache_index, &mut NodeCacheUtil::new(self, node_ref_map));

        match cache_info.get_cache_info() {
            TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot) => {
                self.get_allocator().remove((*slot) as usize).unwrap();
            }
            _ => {}
        }
    }

    unsafe fn delete_cache_evicted_unchecked(
        &self,
        cache_mut: &mut CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        evicted_cache_index: CacheAlgorithmT::CacheIndex,
    )
    {
        // Remove evicted content from cache.
        let cache_info =
            cache_mut.node_ref_map.delete(evicted_cache_index).unwrap();
        match cache_info.get_cache_info() {
            TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot) => {
                self.get_allocator().remove((*slot) as usize).unwrap();
            }
            _ => {}
        }
    }

    unsafe fn delete_cache_evicted_keep_cache_algo_data_unchecked(
        &self,
        cache_mut: &mut CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        evicted_keep_cache_algo_data_cache_index: CacheAlgorithmT::CacheIndex,
    )
    {
        // Remove evicted content from cache.
        // Safe to unwrap because it's guaranteed by cache algorithm that the
        // slot exists.
        let slot = *cache_mut
            .node_ref_map
            .get_cache_info(evicted_keep_cache_algo_data_cache_index)
            .unwrap()
            .get_slot()
            .unwrap() as usize;

        cache_mut.node_ref_map.set_cache_info(
            evicted_keep_cache_algo_data_cache_index,
            CacheableNodeRefDeltaMpt::new(
                TrieCacheSlotOrCacheAlgoData::CacheAlgoData(
                    self.get_allocator()
                        .get_unchecked(slot)
                        .get_ref()
                        .cache_algo_data,
                ),
            ),
        );
        self.get_allocator().remove(slot).unwrap();
    }

    // TODO(yz): special thread local batching logic for access_hit?
    pub fn call_cache_algorithm_access(
        &self,
        cache_mut: &mut CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        cache_index: CacheAlgorithmT::CacheIndex,
    )
    {
        let cache_access_result;
        {
            let mut cache_store_util =
                NodeCacheUtil::new(self, &mut cache_mut.node_ref_map);
            cache_access_result = cache_mut
                .cache_algorithm
                .access(cache_index, &mut cache_store_util);
        }
        match cache_access_result {
            CacheAccessResult::MissReplaced {
                evicted: evicted_cache_indices,
                evicted_keep_cache_algo_data:
                    evicted_keep_cache_algo_data_cache_indices,
            } => unsafe {
                for evicted_cache_index in evicted_cache_indices {
                    self.delete_cache_evicted_unchecked(
                        cache_mut,
                        evicted_cache_index,
                    );
                }
                for evicted_keep_cache_algo_data_cache_index in
                    evicted_keep_cache_algo_data_cache_indices
                {
                    self.delete_cache_evicted_keep_cache_algo_data_unchecked(
                        cache_mut,
                        evicted_keep_cache_algo_data_cache_index,
                    );
                }
            },
            _ => {}
        }
    }

    /// Get mutable reference to TrieNode from dirty (owned) trie node. There is
    /// no need to lock cache manager in this case.
    ///
    /// unsafe because it's unchecked that the node is dirty.
    pub unsafe fn dirty_node_as_mut_unchecked<'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        node: &mut NodeRefDeltaMpt,
    ) -> &'a mut MemOptimizedTrieNode<CacheAlgoDataT>
    {
        match node {
            NodeRefDeltaMpt::Committed { db_key: _ } => {
                unreachable_unchecked();
            }
            NodeRefDeltaMpt::Dirty { ref index } => NodeMemoryManager::<
                CacheAlgoDataT,
                CacheAlgorithmT,
            >::get_in_memory_node_mut(
                &allocator,
                *index as usize,
            ),
        }
    }

    /// Unsafe because node is assumed to be committed.
    unsafe fn load_unowned_node_cell_internal_unchecked<'c: 'a, 'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        node: NodeRefDeltaMpt,
        cache_manager: &'c Mutex<
            CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        >,
        db: &mut DeltaDbOwnedReadTraitObj, mpt_id: DeltaMptId,
        is_loaded_from_db: &mut bool,
    ) -> Result<
        GuardedValue<
            Option<
                MutexGuard<
                    'c,
                    CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
                >,
            >,
            &'a TrieNodeCell<CacheAlgoDataT>,
        >,
    >
    {
        match node {
            NodeRefDeltaMpt::Committed { ref db_key } => {
                let mut cache_manager_mut_wrapped = Some(cache_manager.lock());

                let maybe_cache_slot = cache_manager_mut_wrapped
                    .as_mut()
                    .unwrap()
                    .node_ref_map
                    .get_cache_info((mpt_id, *db_key))
                    .and_then(|x| x.get_slot());

                let trie_node = match maybe_cache_slot {
                    Some(cache_slot) => {
                        // Fast path.
                        NodeMemoryManager::<
                            CacheAlgoDataT,
                            CacheAlgorithmT,
                        >::get_in_memory_cell(
                            &allocator, *cache_slot as usize
                        )
                    }
                    None => {
                        // Slow path, load from db
                        // Release the lock in fast path to prevent deadlock.
                        cache_manager_mut_wrapped.take();

                        // The mutex is used. The preceding underscore is only
                        // to make compiler happy.
                        let _db_load_mutex = self.db_load_lock.lock();
                        cache_manager_mut_wrapped = Some(cache_manager.lock());
                        let maybe_cache_slot = cache_manager_mut_wrapped
                            .as_mut()
                            .unwrap()
                            .node_ref_map
                            .get_cache_info((mpt_id, *db_key))
                            .and_then(|x| x.get_slot());

                        match maybe_cache_slot {
                            Some(cache_slot) => NodeMemoryManager::<
                                CacheAlgoDataT,
                                CacheAlgorithmT,
                            >::get_in_memory_cell(
                                &allocator,
                                *cache_slot as usize,
                            ),
                            None => {
                                // We would like to release the lock to
                                // cache_manager during db IO.
                                cache_manager_mut_wrapped.take();

                                let (guard, loaded_trie_node) = self
                                    .load_from_db(
                                        allocator,
                                        cache_manager,
                                        db,
                                        mpt_id,
                                        *db_key,
                                    )?
                                    .into();

                                cache_manager_mut_wrapped = Some(guard);

                                *is_loaded_from_db = true;

                                loaded_trie_node
                            }
                        }
                    }
                };

                self.call_cache_algorithm_access(
                    cache_manager_mut_wrapped.as_mut().unwrap(),
                    (mpt_id, *db_key),
                );

                Ok(GuardedValue::new(cache_manager_mut_wrapped, trie_node))
            }
            NodeRefDeltaMpt::Dirty { index: _ } => unreachable_unchecked(),
        }
    }

    // FIXME: pass a cache manager / node_ref_map to prove ownership.
    unsafe fn get_cached_node_mut_unchecked<'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        slot: ActualSlabIndex,
    ) -> &'a mut MemOptimizedTrieNode<CacheAlgoDataT>
    {
        NodeMemoryManager::<CacheAlgoDataT, CacheAlgorithmT>::get_in_memory_node_mut(
            &allocator,
            slot as usize,
        )
    }

    /// cache_manager is assigned a different lifetime because the
    /// RwLockWriteGuard returned can be used independently.
    pub fn node_cell_with_cache_manager<'c: 'a, 'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        node: NodeRefDeltaMpt,
        cache_manager: &'c Mutex<
            CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        >,
        db: &mut DeltaDbOwnedReadTraitObj, mpt_id: DeltaMptId,
        is_loaded_from_db: &mut bool,
    ) -> Result<
        GuardedValue<
            Option<
                MutexGuard<
                    'c,
                    CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
                >,
            >,
            &'a TrieNodeCell<CacheAlgoDataT>,
        >,
    >
    {
        match node {
            NodeRefDeltaMpt::Committed { db_key: _ } => unsafe {
                self.load_unowned_node_cell_internal_unchecked(
                    allocator,
                    node,
                    cache_manager,
                    db,
                    mpt_id,
                    is_loaded_from_db,
                )
            },
            NodeRefDeltaMpt::Dirty { ref index } => unsafe {
                Ok(GuardedValue::new(None, NodeMemoryManager::<
                    CacheAlgoDataT,
                    CacheAlgorithmT,
                >::get_in_memory_cell(
                    &allocator,
                    *index as usize,
                )))
            },
        }
    }

    /// cache_manager is assigned a different lifetime because the
    /// RwLockWriteGuard returned can be used independently.
    pub fn node_as_ref_with_cache_manager<'c: 'a, 'a>(
        &self, allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
        node: NodeRefDeltaMpt,
        cache_manager: &'c Mutex<
            CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
        >,
        db: &mut DeltaDbOwnedReadTraitObj, mpt_id: DeltaMptId,
        is_loaded_from_db: &mut bool,
    ) -> Result<
        GuardedValue<
            Option<
                MutexGuard<
                    'c,
                    CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>,
                >,
            >,
            &'a MemOptimizedTrieNode<CacheAlgoDataT>,
        >,
    >
    {
        self.node_cell_with_cache_manager(
            allocator,
            node,
            cache_manager,
            db,
            mpt_id,
            is_loaded_from_db,
        )
        .map(|gv| {
            let (g, v) = gv.into();
            GuardedValue::new(g, v.get_ref())
        })
    }

    pub fn new_node<'a>(
        allocator: AllocatorRefRef<'a, CacheAlgoDataT>,
    ) -> Result<(
        NodeRefDeltaMpt,
        VacantEntry<'a, TrieNodeCell<CacheAlgoDataT>>,
    )> {
        let vacant_entry = allocator.vacant_entry()?;
        let node = NodeRefDeltaMpt::Dirty {
            index: vacant_entry.key() as ActualSlabIndex,
        };
        Ok((node, vacant_entry))
    }

    /// Usually the node to free is dirty (i.e. not committed), however it's
    /// also possible that the state db commitment fails so that the succeeded
    /// nodes in the commitment should be removed from cache and deleted.
    pub fn free_owned_node(
        &self, node: &mut NodeRefDeltaMpt, mpt_id: DeltaMptId,
    ) {
        let slot = match node {
            NodeRefDeltaMpt::Committed { ref db_key } => {
                let maybe_cache_info =
                    self.cache.lock().node_ref_map.delete((mpt_id, *db_key));
                let maybe_cache_slot = maybe_cache_info
                    .as_ref()
                    .and_then(|cache_info| cache_info.get_slot());

                match maybe_cache_slot {
                    None => return,
                    Some(slot) => *slot,
                }
            }
            NodeRefDeltaMpt::Dirty { ref index } => *index,
        };

        // A strong assertion that the remove should success. Otherwise it's a
        // bug.
        self.get_allocator().remove(slot as usize).unwrap();
    }

    pub fn log_usage(&self) {
        self.cache.lock().log_usage();
        let allocator_ref = self.get_allocator();
        debug!(
            "trie node allocator: max allowed size: {}, \
             configured idle_size: {}, size: {}, allocated: {}",
            self.size_limit,
            self.idle_size,
            allocator_ref.capacity(),
            allocator_ref.len()
        );
        debug!(
            "number of nodes loaded from db {}",
            self.db_load_counter.load(Ordering::Relaxed)
        );
        debug!(
            "number of uncached leaf node loads {}",
            self.uncached_leaf_load_times.load(Ordering::Relaxed)
        );
        debug!(
            "number of db loads for uncached leaf nodes {}",
            self.uncached_leaf_db_loads.load(Ordering::Relaxed)
        );
        debug!(
            "number of db loads for merkle computation {}",
            self.compute_merkle_db_loads.load(Ordering::Relaxed)
        );
        debug!(
            "number of db loads for children merkles {}",
            self.children_merkle_db_loads.load(Ordering::Relaxed)
        );
    }
}

struct NodeCacheUtil<
    'a,
    CacheAlgoDataT: CacheAlgoDataTrait,
    CacheAlgorithmT: CacheAlgorithm<CacheAlgoData = CacheAlgoDataT>,
> {
    node_memory_manager: &'a NodeMemoryManager<CacheAlgoDataT, CacheAlgorithmT>,
    node_ref_map: &'a mut NodeRefMapDeltaMpts<CacheAlgoDataT>,
}

impl<
        'a,
        CacheAlgoDataT: CacheAlgoDataTrait,
        CacheAlgorithmT: CacheAlgorithm<CacheAlgoData = CacheAlgoDataT>,
    > NodeCacheUtil<'a, CacheAlgoDataT, CacheAlgorithmT>
{
    fn new(
        node_memory_manager: &'a NodeMemoryManager<
            CacheAlgoDataT,
            CacheAlgorithmT,
        >,
        node_ref_map: &'a mut NodeRefMapDeltaMpts<CacheAlgoDataT>,
    ) -> Self
    {
        NodeCacheUtil {
            node_memory_manager,
            node_ref_map,
        }
    }
}

impl<
        'a,
        CacheAlgoDataT: CacheAlgoDataTrait,
        CacheAlgorithmT: CacheAlgorithm<
            CacheAlgoData = CacheAlgoDataT,
            CacheIndex = (DeltaMptId, DeltaMptDbKey),
        >,
    > CacheStoreUtil for NodeCacheUtil<'a, CacheAlgoDataT, CacheAlgorithmT>
{
    type CacheAlgoData = CacheAlgoDataT;
    type ElementIndex = CacheAlgorithmT::CacheIndex;

    fn get(&self, cache_idnex: Self::ElementIndex) -> Self::CacheAlgoData {
        match self
            .node_ref_map
            .get_cache_info(cache_idnex)
            .unwrap()
            .get_cache_info()
        {
            TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot) => {
                let allocator = self.node_memory_manager.get_allocator();
                unsafe {
                    self.node_memory_manager
                        .get_cached_node_mut_unchecked(&allocator, *slot)
                        .cache_algo_data
                }
            }
            TrieCacheSlotOrCacheAlgoData::CacheAlgoData(cache_algo_data) => {
                cache_algo_data.clone()
            }
        }
    }

    fn set(
        &mut self, cache_index: Self::ElementIndex,
        algo_data: &Self::CacheAlgoData,
    )
    {
        match self
            .node_ref_map
            .get_cache_info(cache_index)
            .unwrap()
            .get_cache_info()
        {
            TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot) => {
                let allocator = self.node_memory_manager.get_allocator();
                unsafe {
                    self.node_memory_manager
                        .get_cached_node_mut_unchecked(&allocator, *slot)
                        .cache_algo_data = *algo_data;
                }
            }
            TrieCacheSlotOrCacheAlgoData::CacheAlgoData(_) => {
                self.node_ref_map.set_cache_info(
                    cache_index,
                    CacheableNodeRefDeltaMpt::new(
                        TrieCacheSlotOrCacheAlgoData::CacheAlgoData(*algo_data),
                    ),
                );
            }
        }
    }
}

use super::{
    super::{
        super::{
            storage_db::delta_db_manager::DeltaDbOwnedReadTraitObj,
            utils::{guarded_value::*, UnsafeCellExtension},
        },
        errors::*,
        merkle_patricia_trie::children_table::*,
    },
    cache::algorithm::{
        lru::LRU, CacheAccessResult, CacheAlgoDataTrait, CacheAlgorithm,
        CacheIndexTrait, CacheStoreUtil,
    },
    cache_manager_delta_mpts::CacheManagerDeltaMpts,
    mem_optimized_trie_node::MemOptimizedTrieNode,
    node_ref_map::*,
    slab::Slab,
    NodeRefDeltaMpt,
};
use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard};
use primitives::MerkleHash;
use rlp::*;
use std::{
    cell::UnsafeCell,
    hint::unreachable_unchecked,
    sync::atomic::{AtomicUsize, Ordering},
};
