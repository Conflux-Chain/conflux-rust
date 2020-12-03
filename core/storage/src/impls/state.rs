// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type ChildrenMerkleMap =
    BTreeMap<ActualSlabIndex, VanillaChildrenTable<MerkleHash>>;

pub struct State {
    manager: Arc<StateManager>,
    snapshot_db: Arc<SnapshotDb>,
    snapshot_epoch_id: EpochId,
    snapshot_merkle_root: MerkleHash,
    maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
    intermediate_trie_root: Option<NodeRefDeltaMpt>,
    intermediate_trie_root_merkle: MerkleHash,
    /// A None value indicate the special case when snapshot_db is actually the
    /// snapshot_db from the intermediate_epoch_id.
    maybe_intermediate_trie_key_padding: Option<DeltaMptKeyPadding>,
    delta_trie: Arc<DeltaMpt>,
    delta_trie_root: Option<NodeRefDeltaMpt>,
    delta_trie_key_padding: DeltaMptKeyPadding,
    intermediate_epoch_id: EpochId,
    delta_trie_height: Option<u32>,
    height: Option<u64>,
    owned_node_set: Option<OwnedNodeSet>,
    dirty: bool,

    /// Children merkle hashes. Only used for committing and computing
    /// merkle root. It will be cleared after being committed.
    children_merkle_map: ChildrenMerkleMap,

    // FIXME: this is a hack to get pivot chain from parent snapshot to a
    // FIXME: snapshot. it should be done in consensus.
    parent_epoch_id: EpochId,
}

impl State {
    pub fn new(manager: Arc<StateManager>, state_trees: StateTrees) -> Self {
        Self {
            manager,
            snapshot_db: state_trees.snapshot_db,
            snapshot_epoch_id: state_trees.snapshot_epoch_id,
            snapshot_merkle_root: state_trees.snapshot_merkle_root,
            maybe_intermediate_trie: state_trees.maybe_intermediate_trie,
            intermediate_trie_root: state_trees.intermediate_trie_root,
            intermediate_trie_root_merkle: state_trees
                .intermediate_trie_root_merkle,
            maybe_intermediate_trie_key_padding: state_trees
                .maybe_intermediate_trie_key_padding,
            delta_trie: state_trees.delta_trie,
            delta_trie_root: state_trees.delta_trie_root,
            delta_trie_key_padding: state_trees.delta_trie_key_padding,
            intermediate_epoch_id: state_trees.intermediate_epoch_id,
            delta_trie_height: state_trees.maybe_delta_trie_height,
            height: state_trees.maybe_height,
            owned_node_set: Some(Default::default()),
            dirty: false,
            children_merkle_map: ChildrenMerkleMap::new(),
            parent_epoch_id: state_trees.parent_epoch_id,
        }
    }

    fn state_root(&self, merkle_root: MerkleHash) -> StateRootWithAuxInfo {
        let state_root = StateRoot {
            snapshot_root: self.snapshot_merkle_root,
            intermediate_delta_root: self.intermediate_trie_root_merkle,
            delta_root: merkle_root,
        };
        let state_root_hash = state_root.compute_state_root_hash();
        StateRootWithAuxInfo {
            state_root,
            aux_info: StateRootAuxInfo {
                snapshot_epoch_id: self.snapshot_epoch_id.clone(),
                intermediate_epoch_id: self.intermediate_epoch_id.clone(),
                maybe_intermediate_mpt_key_padding: self
                    .maybe_intermediate_trie_key_padding
                    .clone(),
                delta_mpt_key_padding: self.delta_trie_key_padding.clone(),
                state_root_hash,
            },
        }
    }

    fn check_freshly_synced_snapshot(&self, op: &'static str) -> Result<()> {
        // Can't offer proof if we are operating on a synced snapshot, which is
        // missing intermediate mpt.
        if self.maybe_intermediate_trie_key_padding.is_some()
            || self.intermediate_epoch_id == NULL_EPOCH
        {
            Ok(())
        } else {
            Err(ErrorKind::UnsupportedByFreshlySyncedSnapshot(op).into())
        }
    }

    fn get_from_delta<WithProof: StaticBool>(
        &self, mpt: &DeltaMpt, maybe_root_node: Option<NodeRefDeltaMpt>,
        access_key: &[u8],
    ) -> Result<(MptValue<Box<[u8]>>, Option<TrieProof>)>
    {
        // Get won't create any new nodes so it's fine to pass an empty
        // owned_node_set.
        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());

        match maybe_root_node {
            None => Ok((MptValue::None, None)),
            Some(root_node) => {
                let maybe_value = SubTrieVisitor::new(
                    mpt,
                    root_node.clone(),
                    &mut empty_owned_node_set,
                )?
                .get(access_key)?;

                let maybe_proof = match WithProof::value() {
                    false => None,
                    true => Some(
                        SubTrieVisitor::new(
                            mpt,
                            root_node,
                            &mut empty_owned_node_set,
                        )?
                        .get_proof(access_key)?,
                    ),
                };

                Ok((maybe_value, maybe_proof))
            }
        }
    }

    pub fn get_from_snapshot<WithProof: StaticBool>(
        &self, access_key: &[u8],
    ) -> Result<(Option<Box<[u8]>>, Option<TrieProof>)> {
        let value = self.snapshot_db.get(access_key)?;
        Ok((
            value,
            if WithProof::value() {
                let mut mpt = self.snapshot_db.open_snapshot_mpt_shared()?;
                let mut cursor = MptCursor::<
                    &mut dyn SnapshotMptTraitRead,
                    BasicPathNode<&mut dyn SnapshotMptTraitRead>,
                >::new(&mut mpt);
                cursor.load_root()?;
                cursor.open_path_for_key::<access_mode::Read>(access_key)?;
                let proof = cursor.to_proof();
                cursor.finish()?;

                Some(proof)
            } else {
                None
            },
        ))
    }

    fn get_from_all_tries<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        let mut proof = StateProof::default();

        let (maybe_value, maybe_delta_proof) = self
            .get_from_delta::<WithProof>(
                &self.delta_trie,
                self.delta_trie_root.clone(),
                &access_key
                    .to_delta_mpt_key_bytes(&self.delta_trie_key_padding),
            )?;
        proof.with_delta(maybe_delta_proof);

        match maybe_value {
            MptValue::Some(value) => {
                return Ok((Some(value), proof));
            }
            MptValue::TombStone => {
                return Ok((None, proof));
            }
            _ => {}
        }

        // FIXME This is for the case of read-only access of the first snapshot
        // state where intermediate_mpt is some.
        if self.maybe_intermediate_trie_key_padding.is_some() {
            if let Some(intermediate_trie) =
                self.maybe_intermediate_trie.as_ref()
            {
                let (maybe_value, maybe_proof) = self
                    .get_from_delta::<WithProof>(
                        intermediate_trie,
                        self.intermediate_trie_root.clone(),
                        &access_key.to_delta_mpt_key_bytes(
                            &self
                                .maybe_intermediate_trie_key_padding
                                .as_ref()
                                .unwrap(),
                        ),
                    )?;

                proof.with_intermediate(maybe_proof);

                match maybe_value {
                    MptValue::Some(value) => {
                        return Ok((Some(value), proof));
                    }
                    MptValue::TombStone => {
                        return Ok((None, proof));
                    }
                    _ => {}
                }
            }
        }

        let (maybe_value, maybe_proof) =
            self.get_from_snapshot::<WithProof>(&access_key.to_key_bytes())?;
        proof.with_snapshot(maybe_proof);

        Ok((maybe_value, proof))
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if self.dirty {
            panic!("State is dirty however is not committed before free.");
        }
    }
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> Result<Option<Box<[u8]>>> {
        self.ensure_temp_slab_for_db_load();

        self.get_from_all_tries::<NoProof>(access_key)
            .map(|(value, _)| value)
    }

    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        self.ensure_temp_slab_for_db_load();

        self.check_freshly_synced_snapshot("proof")?;
        self.get_from_all_tries::<WithProof>(access_key)
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> Result<(NodeMerkleTriplet, NodeMerkleProof)> {
        self.check_freshly_synced_snapshot("proof")?;
        let mut proof = NodeMerkleProof::default();

        // ----------- get from delta -----------
        let delta = match self.delta_trie_root {
            Some(ref root_node) => {
                let key = access_key
                    .to_delta_mpt_key_bytes(&self.delta_trie_key_padding);

                let mut owned_node_set = Some(Default::default());

                let mut visitor = SubTrieVisitor::new(
                    &self.delta_trie,
                    root_node.clone(),
                    // won't create any new nodes
                    &mut owned_node_set,
                )?;

                let delta = visitor.get_merkle_hash_wo_compressed_path(&key)?;

                let maybe_proof = match WithProof::value() {
                    false => None,
                    true => Some(
                        SubTrieVisitor::new(
                            &self.delta_trie,
                            root_node.clone(),
                            // won't create any new nodes
                            &mut Some(Default::default()),
                        )?
                        .get_proof(&key)?,
                    ),
                };

                proof.with_delta(maybe_proof);

                // for tombstones, we ignore the node merkle
                if visitor.get(&key)?.is_tombstone() {
                    MptValue::TombStone
                } else {
                    MptValue::from(delta)
                }
            }
            None => MptValue::None,
        };

        // ----------- get from intermediate -----------
        let intermediate = match (
            &self.intermediate_trie_root,
            &self.maybe_intermediate_trie,
            &self.maybe_intermediate_trie_key_padding,
        ) {
            (
                Some(ref root_node),
                Some(ref intermediate_trie),
                Some(ref intermediate_trie_key_padding),
            ) => {
                let key = access_key
                    .to_delta_mpt_key_bytes(&intermediate_trie_key_padding);

                let mut owned_node_set = Some(Default::default());

                let mut visitor = SubTrieVisitor::new(
                    &intermediate_trie,
                    root_node.clone(),
                    // won't create any new nodes
                    &mut owned_node_set,
                )?;

                let intermediate =
                    visitor.get_merkle_hash_wo_compressed_path(&key)?;

                let maybe_proof = match WithProof::value() {
                    false => None,
                    true => Some(
                        SubTrieVisitor::new(
                            &intermediate_trie,
                            root_node.clone(),
                            // won't create any new nodes
                            &mut Some(Default::default()),
                        )?
                        .get_proof(&key)?,
                    ),
                };

                proof.with_intermediate(maybe_proof);

                // for tombstones, we ignore the node merkle
                if visitor.get(&key)?.is_tombstone() {
                    MptValue::TombStone
                } else {
                    MptValue::from(intermediate)
                }
            }
            _ => MptValue::None,
        };

        // ----------- get from snapshot -----------
        let key = access_key.to_key_bytes();

        let mut mpt = self.snapshot_db.open_snapshot_mpt_shared()?;
        let mut cursor = MptCursor::<
            &mut dyn SnapshotMptTraitRead,
            BasicPathNode<&mut dyn SnapshotMptTraitRead>,
        >::new(&mut mpt);
        cursor.load_root()?;
        let snapshot =
            match cursor.open_path_for_key::<access_mode::Read>(&key)? {
                CursorOpenPathTerminal::Arrived => Some(
                    cursor
                        .current_node_mut()
                        .trie_node
                        .get_merkle_hash_wo_compressed_path(),
                ),
                _ => None,
            };
        let maybe_proof = match WithProof::value() {
            false => None,
            true => Some(cursor.to_proof()),
        };
        cursor.finish()?;
        proof.with_snapshot(maybe_proof);

        let triplet = NodeMerkleTriplet {
            delta,
            intermediate,
            snapshot,
        };

        Ok((triplet, proof))
    }

    fn set(&mut self, access_key: StorageKey, value: Box<[u8]>) -> Result<()> {
        self.pre_modification();

        let root_node = self.get_or_create_delta_root_node()?;
        self.delta_trie_root = SubTrieVisitor::new(
            &self.delta_trie,
            root_node,
            &mut self.owned_node_set,
        )?
        .set(
            &access_key.to_delta_mpt_key_bytes(&self.delta_trie_key_padding),
            value,
        )?
        .into();

        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> Result<()> {
        self.set(access_key, MptValue::<Box<[u8]>>::TombStone.unwrap())?;
        Ok(())
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> Result<Option<Box<[u8]>>> {
        self.pre_modification();

        match self.get_delta_root_node() {
            None => Ok(None),
            Some(old_root_node) => {
                let (old_value, _, root_node) = SubTrieVisitor::new(
                    &self.delta_trie,
                    old_root_node,
                    &mut self.owned_node_set,
                )?
                .delete(
                    &access_key
                        .to_delta_mpt_key_bytes(&self.delta_trie_key_padding),
                )?;
                self.delta_trie_root =
                    root_node.map(|maybe_node| maybe_node.into());
                Ok(old_value)
            }
        }
    }

    /// Delete all key/value pairs with access_key_prefix as prefix. These
    /// key/value pairs exist in three places: Delta Trie, Intermediate Trie
    /// and Snapshot DB.
    ///
    /// For key/value pairs in Delta Trie, we can simply delete them. For
    /// key/value pairs in Intermediate Trie and Snapshot DB, we try to
    /// enumerate all key/value pairs and set tombstone in Delta Trie only when
    /// necessary.
    ///
    /// When AM is Read, only calculate the key values to be deleted.
    fn delete_all<AM: access_mode::AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        if AM::is_read_only() {
            self.ensure_temp_slab_for_db_load();
        } else {
            self.pre_modification();
        }

        // Retrieve and delete key/value pairs from delta trie
        let delta_trie_kvs = match &self.delta_trie_root {
            None => None,
            Some(old_root_node) => {
                let delta_mpt_key_prefix = access_key_prefix
                    .to_delta_mpt_key_bytes(&self.delta_trie_key_padding);
                let deleted = if AM::is_read_only() {
                    SubTrieVisitor::new(
                        &self.delta_trie,
                        old_root_node.clone(),
                        &mut self.owned_node_set,
                    )?
                    .traversal(&delta_mpt_key_prefix, &delta_mpt_key_prefix)?
                } else {
                    let (deleted, _, root_node) = SubTrieVisitor::new(
                        &self.delta_trie,
                        old_root_node.clone(),
                        &mut self.owned_node_set,
                    )?
                    .delete_all(&delta_mpt_key_prefix, &delta_mpt_key_prefix)?;
                    self.delta_trie_root =
                        root_node.map(|maybe_node| maybe_node.into());

                    deleted
                };
                deleted
            }
        };

        // Retrieve key/value pairs from intermediate trie
        let intermediate_trie_kvs = match &self.intermediate_trie_root {
            None => None,
            Some(root_node) => {
                if self.maybe_intermediate_trie_key_padding.is_some()
                    && self.maybe_intermediate_trie.is_some()
                {
                    let intermediate_trie_key_padding = self
                        .maybe_intermediate_trie_key_padding
                        .as_ref()
                        .unwrap();
                    let intermediate_mpt_key_prefix = access_key_prefix
                        .to_delta_mpt_key_bytes(intermediate_trie_key_padding);
                    let values = SubTrieVisitor::new(
                        self.maybe_intermediate_trie.as_ref().unwrap(),
                        root_node.clone(),
                        &mut self.owned_node_set,
                    )?
                    .traversal(
                        &intermediate_mpt_key_prefix,
                        &intermediate_mpt_key_prefix,
                    )?;

                    values
                } else {
                    None
                }
            }
        };

        // Retrieve key/value pairs from snapshot
        let mut kv_iterator = self.snapshot_db.snapshot_kv_iterator()?.take();
        let lower_bound_incl = access_key_prefix.to_key_bytes();
        let upper_bound_excl =
            to_key_prefix_iter_upper_bound(&lower_bound_incl);
        let mut kvs = kv_iterator
            .iter_range(
                lower_bound_incl.as_slice(),
                upper_bound_excl.as_ref().map(|v| &**v),
            )?
            .take();

        let mut snapshot_kvs = Vec::new();
        while let Some((key, value)) = kvs.next()? {
            snapshot_kvs.push((key, value));
        }

        let mut result = Vec::new();
        // This is used to keep track of the deleted keys.
        let mut deleted_keys = HashSet::new();
        if let Some(kvs) = delta_trie_kvs {
            for (k, v) in kvs {
                let storage_key = StorageKey::from_delta_mpt_key(&k);
                let k = storage_key.to_key_bytes();
                deleted_keys.insert(k.clone());
                if v.len() > 0 {
                    result.push((k, v));
                }
            }
        }

        if let Some(kvs) = intermediate_trie_kvs {
            for (k, v) in kvs {
                let storage_key = StorageKey::from_delta_mpt_key(&k);
                // Only delete non-empty keys.
                if v.len() > 0 && !AM::is_read_only() {
                    self.delete(storage_key)?;
                }
                let k = storage_key.to_key_bytes();
                if !deleted_keys.contains(&k) {
                    deleted_keys.insert(k.clone());
                    if v.len() > 0 {
                        result.push((k, v));
                    }
                }
            }
        }

        // No need to check v.len() because there are no tombStone values in
        // snapshot.
        for (k, v) in snapshot_kvs {
            let storage_key = StorageKey::from_key_bytes::<SkipInputCheck>(&k);
            if !AM::is_read_only() {
                self.delete(storage_key)?;
            }
            if !deleted_keys.contains(&k) {
                result.push((k, v));
            }
        }

        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        self.ensure_temp_slab_for_db_load();

        let merkle_root = self.compute_merkle_root()?;
        Ok(self.state_root(merkle_root))
    }

    fn get_state_root(&self) -> Result<StateRootWithAuxInfo> {
        self.ensure_temp_slab_for_db_load();

        Ok(self.state_root(self.state_root_check()?))
    }

    // TODO(yz): replace coarse lock with a queue.
    fn commit(&mut self, epoch_id: EpochId) -> Result<StateRootWithAuxInfo> {
        self.ensure_temp_slab_for_db_load();

        let merkle_root = self.state_root_check()?;

        // TODO(yz): Think about leaving these node dirty and only commit when
        // the dirty node is removed from cache.
        let commit_result = self.do_db_commit(epoch_id, &merkle_root);
        debug!(
            "commit state for epoch {:?}: merkle_root = {:?}, delta_trie_height={:?} \
            has_intermediate={}, height={:?}, snapshot_epoch_id={:?}, \
            intermediate_epoch_id={:?}, intermediate_mpt_id={:?}, delta_mpt_id={}.",
            epoch_id,
            merkle_root,
            self.delta_trie_height,
            self.maybe_intermediate_trie.is_some(),
            self.height,
            self.snapshot_epoch_id,
            self.intermediate_epoch_id,
            self.maybe_intermediate_trie.as_ref().map(|mpt| mpt.get_mpt_id()),
            self.delta_trie.get_mpt_id(),
        );
        if commit_result.is_err() {
            self.revert();
            debug!("State commitment failed.");

            commit_result?;
        }
        if self.delta_trie_height.unwrap()
            >= self
                .manager
                .get_storage_manager()
                .get_snapshot_epoch_count()
                / 3
            && self.maybe_intermediate_trie.is_some()
        {
            // TODO: use a better criteria and put it in consensus maybe.
            let snapshot_height = self.height.clone().unwrap()
                - self.delta_trie_height.unwrap() as u64;
            self.manager.check_make_snapshot(
                self.maybe_intermediate_trie.clone(),
                self.intermediate_trie_root.clone(),
                &self.intermediate_epoch_id,
                snapshot_height,
            )?;
        }

        Ok(self.state_root(merkle_root))
    }

    fn revert(&mut self) {
        self.dirty = false;

        // Free all modified nodes.
        let owned_node_set = self.owned_node_set.as_ref().unwrap();
        for owned_node in owned_node_set {
            self.delta_trie.get_node_memory_manager().free_owned_node(
                &mut owned_node.clone(),
                self.delta_trie.get_mpt_id(),
            );
        }
    }
}

impl State {
    fn ensure_temp_slab_for_db_load(&self) {
        self.delta_trie.get_node_memory_manager().enlarge().ok();
    }

    fn pre_modification(&mut self) {
        if !self.dirty {
            self.dirty = true
        }
        self.delta_trie.get_node_memory_manager().enlarge().ok();
    }

    fn get_delta_root_node(&self) -> Option<NodeRefDeltaMpt> {
        self.delta_trie_root.clone()
    }

    fn get_or_create_delta_root_node(&mut self) -> Result<NodeRefDeltaMpt> {
        if self.delta_trie_root.is_none() {
            let allocator =
                self.delta_trie.get_node_memory_manager().get_allocator();
            let (root_cow, entry) = CowNodeRef::new_uninitialized_node(
                &allocator,
                self.owned_node_set.as_mut().unwrap(),
                self.delta_trie.get_mpt_id(),
            )?;
            // Insert empty node.
            entry.insert(UnsafeCell::new(Default::default()));

            self.delta_trie_root =
                root_cow.into_child().map(|maybe_node| maybe_node.into());
        }

        // Safe because in either branch the result is Some.
        Ok(self.get_delta_root_node().unwrap())
    }

    fn compute_merkle_root(&mut self) -> Result<MerkleHash> {
        assert!(self.children_merkle_map.len() == 0);

        match &self.delta_trie_root {
            None => {
                // Don't commit empty state. Empty state shouldn't exists since
                // genesis block.
                Ok(MERKLE_NULL_NODE)
            }
            Some(root_node) => {
                let mut cow_root = CowNodeRef::new(
                    root_node.clone(),
                    self.owned_node_set.as_ref().unwrap(),
                    self.delta_trie.get_mpt_id(),
                );
                let allocator =
                    self.delta_trie.get_node_memory_manager().get_allocator();
                let merkle = cow_root.get_or_compute_merkle(
                    &self.delta_trie,
                    self.owned_node_set.as_mut().unwrap(),
                    &allocator,
                    &mut *self.delta_trie.db_owned_read()?,
                    &mut self.children_merkle_map,
                    0,
                )?;
                cow_root.into_child();

                Ok(merkle)
            }
        }
    }

    fn do_db_commit(
        &mut self, epoch_id: EpochId, merkle_root: &MerkleHash,
    ) -> Result<()> {
        let maybe_existing_merkle_root =
            self.delta_trie.get_merkle_root_by_epoch_id(&epoch_id)?;
        if maybe_existing_merkle_root.is_some() {
            // TODO This may happen for genesis when we restart
            info!(
                "Overwriting computed state for epoch {:?}, \
                 committed merkle root {:?}, new merkle root {:?}",
                epoch_id,
                maybe_existing_merkle_root.unwrap(),
                merkle_root
            );
            assert_eq!(
                maybe_existing_merkle_root,
                Some(*merkle_root),
                "Overwriting computed state with a different merkle root."
            );
            self.revert();
            return Ok(());
        }

        // Use coarse lock to prevent row number from interleaving,
        // which makes it cleaner to restart from db failure. It also
        // benefits performance because without a coarse lock all
        // threads may not be able to do anything else when they compete
        // with each other on slow db writing.
        let mut commit_transaction = self.delta_trie.start_commit()?;

        let maybe_root_node = self.delta_trie_root.clone();
        match maybe_root_node {
            None => {}
            Some(root_node) => {
                let start_row_number = commit_transaction.info.row_number.value;

                let mut cow_root = CowNodeRef::new(
                    root_node,
                    self.owned_node_set.as_ref().unwrap(),
                    self.delta_trie.get_mpt_id(),
                );

                if cow_root.is_owned() {
                    let allocator = self
                        .delta_trie
                        .get_node_memory_manager()
                        .get_allocator();
                    let trie_node_mut = unsafe {
                        self.delta_trie
                            .get_node_memory_manager()
                            .dirty_node_as_mut_unchecked(
                                &allocator,
                                &mut cow_root.node_ref,
                            )
                    };
                    let result = cow_root.commit_dirty_recursively(
                        &self.delta_trie,
                        self.owned_node_set.as_mut().unwrap(),
                        trie_node_mut,
                        &mut commit_transaction,
                        &mut *self
                            .delta_trie
                            .get_node_memory_manager()
                            .get_cache_manager()
                            .lock(),
                        &allocator,
                        &mut self.children_merkle_map,
                    );
                    self.children_merkle_map.clear();
                    self.delta_trie_root =
                        cow_root.into_child().map(|r| r.into());
                    result?;

                    // TODO: check the guarantee of underlying db on transaction
                    // TODO: failure. may have to commit last_row_number
                    // TODO: separately in worst case.
                    commit_transaction.transaction.put(
                        "last_row_number".as_bytes(),
                        commit_transaction
                            .info
                            .row_number
                            .to_string()
                            .as_bytes(),
                    )?;
                }

                let db_key = *{
                    match self.delta_trie_root.as_ref().unwrap() {
                        // Dirty state are committed.
                        NodeRefDeltaMpt::Dirty { index: _ } => unsafe {
                            unreachable_unchecked();
                        },
                        // Empty block's state root points to its base state.
                        NodeRefDeltaMpt::Committed { db_key } => db_key,
                    }
                };

                commit_transaction.transaction.put(
                    ["db_key_for_epoch_id_".as_bytes(), epoch_id.as_ref()]
                        .concat()
                        .as_slice(),
                    db_key.to_string().as_bytes(),
                )?;

                commit_transaction.transaction.put(
                    ["db_key_for_root_".as_bytes(), merkle_root.as_ref()]
                        .concat()
                        .as_slice(),
                    db_key.to_string().as_bytes(),
                )?;

                self.manager.number_committed_nodes.fetch_add(
                    (commit_transaction.info.row_number.value
                        - start_row_number) as usize,
                    Ordering::Relaxed,
                );
            }
        }

        commit_transaction.transaction.put(
            ["parent_epoch_id_".as_bytes(), epoch_id.as_ref()]
                .concat()
                .as_slice(),
            self.parent_epoch_id.as_ref().to_hex().as_bytes(),
        )?;

        commit_transaction
            .transaction
            .commit(self.delta_trie.db_commit())?;

        self.delta_trie.state_root_committed(
            epoch_id,
            merkle_root,
            self.parent_epoch_id,
            self.delta_trie_root.clone(),
        );

        self.dirty = false;

        Ok(())
    }

    fn state_root_check(&self) -> Result<MerkleHash> {
        let maybe_merkle_root =
            self.delta_trie.get_merkle(self.delta_trie_root.clone())?;
        match maybe_merkle_root {
            // Empty state.
            None => (Ok(MERKLE_NULL_NODE)),
            Some(merkle_hash) => {
                // Non-empty state
                if merkle_hash.is_zero() {
                    Err(ErrorKind::StateCommitWithoutMerkleHash.into())
                } else {
                    Ok(merkle_hash)
                }
            }
        }
    }

    pub fn dump<DUMPER: KVInserter<MptKeyValue>>(
        &self, dumper: &mut DUMPER,
    ) -> Result<()> {
        let inserter = DeltaMptIterator {
            mpt: self.delta_trie.clone(),
            maybe_root_node: self.delta_trie_root.clone(),
        };

        inserter.iterate(dumper)
    }
}

use crate::{
    impls::{
        delta_mpt::{node_memory_manager::ActualSlabIndex, *},
        errors::*,
        merkle_patricia_trie::{
            mpt_cursor::{BasicPathNode, CursorOpenPathTerminal, MptCursor},
            KVInserter, MptKeyValue, TrieProof, VanillaChildrenTable,
        },
        node_merkle_proof::NodeMerkleProof,
        state_manager::*,
        state_proof::StateProof,
    },
    state::*,
    storage_db::*,
    utils::{access_mode, to_key_prefix_iter_upper_bound},
};
use cfx_internal_common::{StateRootAuxInfo, StateRootWithAuxInfo};
use fallible_iterator::FallibleIterator;
use primitives::{
    DeltaMptKeyPadding, EpochId, MerkleHash, MptValue, NodeMerkleTriplet,
    SkipInputCheck, StateRoot, StaticBool, StorageKey, MERKLE_NULL_NODE,
    NULL_EPOCH,
};
use rustc_hex::ToHex;
use std::{
    cell::UnsafeCell,
    collections::{BTreeMap, HashSet},
    hint::unreachable_unchecked,
    sync::{atomic::Ordering, Arc},
};
