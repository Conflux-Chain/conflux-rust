use crate::{
    impls::{errors::*, state::ChildrenMerkleMap},
    state::StateTrait,
    utils::access_mode,
    CowNodeRef, DeltaMpt, MptKeyValue, NodeRefDeltaMpt, OwnedNodeSet,
    SubTrieVisitor,
};
use cfx_internal_common::{StateRootAuxInfo, StateRootWithAuxInfo};
use primitives::{
    EpochId, MerkleHash, MptValue, StateRoot, StorageKeyWithSpace,
    MERKLE_NULL_NODE,
};
use std::{
    cell::UnsafeCell, collections::HashSet, hint::unreachable_unchecked,
    sync::Arc,
};

pub struct SingleMptState {
    trie: Arc<DeltaMpt>,
    trie_root: NodeRefDeltaMpt,

    owned_node_set: Option<OwnedNodeSet>,
    dirty: bool,
    /// Children merkle hashes. Only used for committing and computing
    /// merkle root. It will be cleared after being committed.
    children_merkle_map: ChildrenMerkleMap,
}

impl SingleMptState {
    pub fn new(trie: Arc<DeltaMpt>, trie_root: NodeRefDeltaMpt) -> Self {
        debug!("single_mpt::new: root={:?}", trie_root);
        Self {
            trie,
            trie_root,
            owned_node_set: Some(Default::default()),
            dirty: false,
            children_merkle_map: Default::default(),
        }
    }

    pub fn new_empty(trie: Arc<DeltaMpt>) -> Self {
        let mut owned_node_set = Default::default();

        let trie_root = {
            let allocator = trie.get_node_memory_manager().get_allocator();
            let (root_cow, entry) = CowNodeRef::new_uninitialized_node(
                &allocator,
                &mut owned_node_set,
                0,
            )
            .expect("allocator error");
            // Insert empty node.
            entry.insert(UnsafeCell::new(Default::default()));
            root_cow.into_child().unwrap().into()
        };
        Self {
            trie,
            trie_root,
            owned_node_set: Some(owned_node_set),
            dirty: false,
            children_merkle_map: Default::default(),
        }
    }

    fn ensure_temp_slab_for_db_load(&self) {
        self.trie.get_node_memory_manager().enlarge().ok();
    }

    fn pre_modification(&mut self) {
        if !self.dirty {
            self.dirty = true
        }
        self.trie.get_node_memory_manager().enlarge().ok();
    }

    fn revert(&mut self) {
        self.dirty = false;

        // Free all modified nodes.
        let owned_node_set = self.owned_node_set.as_ref().unwrap();
        for owned_node in owned_node_set {
            self.trie.get_node_memory_manager().free_owned_node(
                &mut owned_node.clone(),
                self.trie.get_mpt_id(),
            );
        }
    }

    fn state_root_check(&self) -> Result<MerkleHash> {
        let maybe_merkle_root =
            self.trie.get_merkle(Some(self.trie_root.clone()))?;
        match maybe_merkle_root {
            // Empty state.
            None => Ok(MERKLE_NULL_NODE),
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

    fn state_root(&self, merkle_root: MerkleHash) -> StateRootWithAuxInfo {
        let state_root = StateRoot {
            snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_root: MERKLE_NULL_NODE,
            delta_root: merkle_root,
        };
        let state_root_hash = state_root.compute_state_root_hash();
        StateRootWithAuxInfo {
            state_root,
            // aux_info will not be used.
            aux_info: StateRootAuxInfo::genesis_state_root_aux_info(
                &state_root_hash,
            ),
        }
    }

    fn compute_merkle_root(&mut self) -> Result<MerkleHash> {
        debug!(
            "single_mpt::compute_merkle_root: trie_root={:?}",
            self.trie_root
        );
        let mut cow_root = CowNodeRef::new(
            self.trie_root.clone(),
            self.owned_node_set.as_ref().unwrap(),
            self.trie.get_mpt_id(),
        );
        let allocator = self.trie.get_node_memory_manager().get_allocator();
        let arc_db = self.trie.get_arc_db()?;
        let merkle = cow_root.get_or_compute_merkle(
            &self.trie,
            self.owned_node_set.as_mut().unwrap(),
            &allocator,
            &mut *arc_db.to_owned_read()?,
            &mut self.children_merkle_map,
            0,
        )?;
        cow_root.into_child();

        Ok(merkle)
    }

    fn do_db_commit(
        &mut self, epoch_id: EpochId, merkle_root: &MerkleHash,
    ) -> Result<()> {
        let maybe_existing_merkle_root =
            self.trie.get_merkle_root_by_epoch_id(&epoch_id)?;
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
        let mut commit_transaction = self.trie.start_commit()?;

        let mut cow_root = CowNodeRef::new(
            self.trie_root.clone(),
            self.owned_node_set.as_ref().unwrap(),
            self.trie.get_mpt_id(),
        );

        if cow_root.is_owned() {
            let allocator = self.trie.get_node_memory_manager().get_allocator();
            let trie_node_mut = unsafe {
                self.trie
                    .get_node_memory_manager()
                    .dirty_node_as_mut_unchecked(
                        &allocator,
                        &mut cow_root.node_ref,
                    )
            };
            let result = cow_root.commit_dirty_recursively(
                &self.trie,
                self.owned_node_set.as_mut().unwrap(),
                trie_node_mut,
                &mut commit_transaction,
                &mut *self
                    .trie
                    .get_node_memory_manager()
                    .get_cache_manager()
                    .lock(),
                &allocator,
                &mut self.children_merkle_map,
            );
            self.children_merkle_map.clear();
            self.trie_root = cow_root.into_child().map(|r| r.into()).unwrap();
            result?;

            // TODO: check the guarantee of underlying db on transaction
            // TODO: failure. may have to commit last_row_number
            // TODO: separately in worst case.
            commit_transaction.transaction.put(
                "last_row_number".as_bytes(),
                commit_transaction.info.row_number.to_string().as_bytes(),
            )?;
        }

        let db_key = *{
            match &self.trie_root {
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

        {
            let arc_db = self.trie.get_arc_db()?;
            commit_transaction
                .transaction
                .commit(arc_db.db_ref().as_any())?;
        }

        self.trie.state_root_committed(
            epoch_id,
            merkle_root,
            // parent_epoch_id is unused.
            Default::default(),
            Some(self.trie_root.clone()),
        );

        self.dirty = false;

        Ok(())
    }

    fn delete_all_impl<AM: access_mode::AccessMode>(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        if AM::READ_ONLY {
            self.ensure_temp_slab_for_db_load();
        } else {
            self.pre_modification();
        }

        // Retrieve and delete key/value pairs from delta trie
        let trie_kvs = {
            let key_prefix = access_key_prefix.to_key_bytes();
            let deleted = if AM::READ_ONLY {
                SubTrieVisitor::new(
                    &self.trie,
                    self.trie_root.clone(),
                    &mut self.owned_node_set,
                )?
                .traversal(&key_prefix, &key_prefix)?
            } else {
                let (deleted, _, root_node) = SubTrieVisitor::new(
                    &self.trie,
                    self.trie_root.clone(),
                    &mut self.owned_node_set,
                )?
                .delete_all(&key_prefix, &key_prefix)?;
                self.trie_root = root_node.unwrap().into();

                deleted
            };
            deleted
        };

        let mut result = Vec::new();
        // This is used to keep track of the deleted keys.
        let mut deleted_keys = HashSet::new();
        if let Some(kvs) = trie_kvs {
            for (k, v) in kvs {
                let storage_key = StorageKeyWithSpace::from_delta_mpt_key(&k);
                let k = storage_key.to_key_bytes();
                deleted_keys.insert(k.clone());
                if v.len() > 0 {
                    result.push((k, v));
                }
            }
        }
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

impl StateTrait for SingleMptState {
    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        self.ensure_temp_slab_for_db_load();

        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());

        let maybe_value = SubTrieVisitor::new(
            &self.trie,
            self.trie_root.clone(),
            &mut empty_owned_node_set,
        )?
        .get(&access_key.to_key_bytes())?;

        match maybe_value {
            MptValue::Some(value) => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    fn set(
        &mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>,
    ) -> Result<()> {
        self.pre_modification();

        self.trie_root = SubTrieVisitor::new(
            &self.trie,
            self.trie_root.clone(),
            &mut self.owned_node_set,
        )?
        .set(&access_key.to_key_bytes(), value)?
        .into();

        Ok(())
    }

    fn delete(&mut self, access_key: StorageKeyWithSpace) -> Result<()> {
        self.set(access_key, MptValue::<Box<[u8]>>::TombStone.unwrap())?;
        Ok(())
    }

    fn delete_test_only(
        &mut self, _access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        todo!()
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        self.delete_all_impl::<access_mode::Write>(access_key_prefix)
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        self.delete_all_impl::<access_mode::Read>(access_key_prefix)
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
        if commit_result.is_err() {
            self.revert();
            debug!("State commitment failed.");

            commit_result?;
        }
        debug!(
            "single mpt commit: epoch={:?} root={:?}",
            epoch_id, merkle_root
        );
        Ok(self.state_root(merkle_root))
    }
}
