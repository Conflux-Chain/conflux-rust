// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type ChildrenMerkleMap =
    BTreeMap<ActualSlabIndex, VanillaChildrenTable<MerkleHash>>;

// FIXME: remove 'a.
pub struct State<'a> {
    manager: &'a StateManager,
    snapshot_db: SnapshotDb,
    maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
    intermediate_trie_root: Option<NodeRefDeltaMpt>,
    delta_trie: Arc<DeltaMpt>,
    delta_trie_root: Option<NodeRefDeltaMpt>,
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

impl<'a> State<'a> {
    pub fn new(manager: &'a StateManager, state_trees: StateTrees) -> Self {
        Self {
            manager,
            snapshot_db: state_trees.snapshot_db,
            maybe_intermediate_trie: state_trees.maybe_intermediate_trie,
            intermediate_trie_root: state_trees.intermediate_trie_root,
            delta_trie: state_trees.delta_trie,
            delta_trie_root: state_trees.delta_trie_root,
            intermediate_epoch_id: state_trees.intermediate_epoch_id,
            delta_trie_height: state_trees.delta_trie_height,
            height: state_trees.height,
            owned_node_set: Some(Default::default()),
            dirty: false,
            children_merkle_map: ChildrenMerkleMap::new(),

            parent_epoch_id: state_trees.epoch_id,
        }
    }

    fn get_from_delta(
        &self, mpt: &'a DeltaMpt, maybe_root_node: Option<NodeRefDeltaMpt>,
        access_key: &[u8], with_proof: bool,
    ) -> Result<(Option<Box<[u8]>>, Option<TrieProof>)>
    {
        // Get won't create any new nodes so it's fine to pass an empty
        // owned_node_set.
        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());

        match maybe_root_node {
            None => Ok((None, None)),
            Some(root_node) => {
                let maybe_value = SubTrieVisitor::new(
                    mpt,
                    root_node.clone(),
                    &mut empty_owned_node_set,
                )?
                .get(access_key)?;

                let maybe_proof = match with_proof {
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

    // FIXME: the current implementation is serialized, which may not be good.
    pub fn get_from_snapshot(
        &self, access_key: &[u8],
    ) -> Result<Option<Box<[u8]>>> {
        self.snapshot_db.get(access_key)
    }

    fn get_from_all_tries(
        &self, access_key: &[u8], with_proof: bool,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        let (maybe_value, maybe_delta_proof) = self.get_from_delta(
            &self.delta_trie,
            self.delta_trie_root.clone(),
            access_key,
            with_proof,
        )?;

        if maybe_value.is_some() {
            let proof = StateProof::default().with_delta(maybe_delta_proof);
            return Ok((maybe_value, proof));
        }

        let maybe_intermediate_proof =
            match self.maybe_intermediate_trie.as_ref() {
                None => None,
                Some(_) => {
                    let (maybe_value, maybe_proof) = self.get_from_delta(
                        self.maybe_intermediate_trie.as_ref().as_ref().unwrap(),
                        self.intermediate_trie_root.clone(),
                        access_key,
                        with_proof,
                    )?;

                    if maybe_value.is_some() {
                        let proof = StateProof::default()
                            .with_delta(maybe_delta_proof)
                            .with_intermediate(maybe_proof);
                        return Ok((maybe_value, proof));
                    }

                    maybe_proof
                }
            };

        // TODO: get from snapshot
        // self.get_from_snapshot(access_key)

        let proof = StateProof::default()
            .with_delta(maybe_delta_proof)
            .with_intermediate(maybe_intermediate_proof);

        Ok((None, proof))
    }
}

impl<'a> Drop for State<'a> {
    fn drop(&mut self) {
        if self.dirty {
            panic!("State is dirty however is not committed before free.");
        }
    }
}

impl<'a> StateTrait for State<'a> {
    fn does_exist(&self) -> bool { self.get_delta_root_node().is_some() }

    fn get_padding(&self) -> &KeyPadding { &self.delta_trie.padding }

    fn get_merkle_hash(&self, access_key: &[u8]) -> Result<Option<MerkleHash>> {
        // Get won't create any new nodes so it's fine to pass an empty
        // owned_node_set.
        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());
        match self.get_delta_root_node() {
            None => Ok(None),
            Some(root_node) => SubTrieVisitor::new(
                &self.delta_trie,
                root_node,
                &mut empty_owned_node_set,
            )?
            .get_merkle_hash_wo_compressed_path(access_key),
        }
    }

    fn get(&self, access_key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.get_from_all_tries(access_key, false)
            .map(|(value, _)| value)
    }

    fn get_with_proof(
        &self, access_key: &[u8],
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        self.get_from_all_tries(access_key, true)
    }

    fn set(&mut self, access_key: &[u8], value: Box<[u8]>) -> Result<()> {
        self.pre_modification();

        let root_node = self.get_or_create_root_node()?;
        self.delta_trie_root = SubTrieVisitor::new(
            &self.delta_trie,
            root_node,
            &mut self.owned_node_set,
        )?
        .set(access_key, value)?
        .into();

        Ok(())
    }

    fn delete(&mut self, access_key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.pre_modification();

        match self.get_delta_root_node() {
            None => Ok(None),
            Some(old_root_node) => {
                let (old_value, _, root_node) = SubTrieVisitor::new(
                    &self.delta_trie,
                    old_root_node,
                    &mut self.owned_node_set,
                )?
                .delete(access_key)?;
                self.delta_trie_root =
                    root_node.map(|maybe_node| maybe_node.into());
                Ok(old_value)
            }
        }
    }

    fn delete_all(
        &mut self, access_key_prefix: &[u8],
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>> {
        self.pre_modification();

        match self.get_delta_root_node() {
            None => Ok(None),
            Some(old_root_node) => {
                let (deleted, _, root_node) = SubTrieVisitor::new(
                    &self.delta_trie,
                    old_root_node,
                    &mut self.owned_node_set,
                )?
                .delete_all(access_key_prefix, access_key_prefix)?;
                self.delta_trie_root =
                    root_node.map(|maybe_node| maybe_node.into());
                Ok(deleted)
            }
        }
    }

    fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        let merkle_root = self.compute_merkle_root()?;

        Ok(StateRootWithAuxInfo {
            // TODO: fill in real snapshot, intermediate delta, ...
            state_root: StateRoot {
                snapshot_root: MERKLE_NULL_NODE,
                intermediate_delta_root: MERKLE_NULL_NODE,
                delta_root: merkle_root,
            },
            aux_info: Default::default(),
        })
    }

    fn get_state_root(&self) -> Result<Option<StateRootWithAuxInfo>> {
        let merkle_root = self.get_merkle_root()?;
        Ok(merkle_root.map(|merkle_hash| StateRootWithAuxInfo {
            state_root: StateRoot {
                snapshot_root: self
                    .snapshot_db
                    .get_snapshot_info()
                    .merkle_root
                    .clone(),
                // FIXME: implement for intermediate_delta_root.
                intermediate_delta_root: MERKLE_NULL_NODE,
                delta_root: merkle_hash,
            },
            aux_info: StateRootAuxInfo {
                snapshot_epoch_id: self
                    .snapshot_db
                    .get_snapshot_info()
                    .get_snapshot_epoch_id()
                    .clone(),
                intermediate_epoch_id: self.intermediate_epoch_id.clone(),
            },
        }))
    }

    // TODO(yz): replace coarse lock with a queue.
    fn commit(&mut self, epoch_id: EpochId) -> Result<()> {
        let merkle_root = self.state_root_check()?;

        // TODO(yz): Think about leaving these node dirty and only commit when
        // the dirty node is removed from cache.
        let commit_result = self.do_db_commit(epoch_id, &merkle_root);
        if commit_result.is_err() {
            self.revert();
        }

        // TODO: use a better criteria and put it in consensus maybe.
        if self.delta_trie_height.unwrap() as u64
            >= SNAPSHOT_EPOCHS_CAPACITY / 2
        {
            // FIXME: There are 2 cases when intermediate trie is None, we must
            // clarify.
            self.manager.check_make_snapshot(
                self.maybe_intermediate_trie.clone(),
                self.intermediate_trie_root.clone(),
                &self.intermediate_epoch_id,
                self.height.clone().unwrap(),
            )?;
        }

        commit_result
    }

    fn revert(&mut self) {
        self.dirty = false;

        // Free all modified nodes.
        let owned_node_set = self.owned_node_set.as_ref().unwrap();
        for owned_node in owned_node_set {
            self.delta_trie
                .get_node_memory_manager()
                .free_owned_node(&mut owned_node.clone());
        }
    }
}

impl<'a> State<'a> {
    fn pre_modification(&mut self) {
        if !self.dirty {
            self.dirty = true
        }
        self.delta_trie.get_node_memory_manager().enlarge().ok();
    }

    fn get_delta_root_node(&self) -> Option<NodeRefDeltaMpt> {
        self.delta_trie_root.clone()
    }

    pub fn get_or_create_root_node(&mut self) -> Result<NodeRefDeltaMpt> {
        if self.delta_trie_root.is_none() {
            let allocator =
                self.delta_trie.get_node_memory_manager().get_allocator();
            let (root_cow, entry) = CowNodeRef::new_uninitialized_node(
                &allocator,
                self.owned_node_set.as_mut().unwrap(),
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

    fn get_merkle_root(&self) -> Result<Option<MerkleHash>> {
        self.delta_trie.get_merkle(self.delta_trie_root.clone())
    }

    fn do_db_commit(
        &mut self, epoch_id: EpochId, merkle_root: &MerkleHash,
    ) -> Result<()> {
        // TODO(yz): accumulate to db write counter.
        self.dirty = false;

        let maybe_root_node = self.delta_trie_root.clone();
        match maybe_root_node {
            None => {}
            Some(root_node) => {
                // Use coarse lock to prevent row number from interleaving,
                // which makes it cleaner to restart from db failure. It also
                // benefits performance because without a coarse lock all
                // threads may not be able to do anything else when they compete
                // with each other on slow db writing.
                let mut commit_transaction = self.delta_trie.start_commit()?;
                let start_row_number = commit_transaction.info.row_number.value;

                let mut cow_root = CowNodeRef::new(
                    root_node,
                    self.owned_node_set.as_ref().unwrap(),
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

                commit_transaction.transaction.put(
                    ["parent_epoch_id_".as_bytes(), epoch_id.as_ref()]
                        .concat()
                        .as_slice(),
                    self.parent_epoch_id.to_hex().as_bytes(),
                )?;

                commit_transaction
                    .transaction
                    .commit(self.delta_trie.db_commit())?;

                self.manager.number_committed_nodes.fetch_add(
                    (commit_transaction.info.row_number.value
                        - start_row_number) as usize,
                    Ordering::Relaxed,
                );
            }
        }

        StateManager::mpt_commit_state_root(
            &self.delta_trie,
            epoch_id,
            merkle_root,
            self.parent_epoch_id.clone(),
            self.delta_trie_root.clone(),
        );

        Ok(())
    }

    fn state_root_check(&self) -> Result<MerkleHash> {
        let maybe_merkle_root = self.get_merkle_root()?;
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

    pub fn dump<DUMPER: KVInserter<(Vec<u8>, Box<[u8]>)>>(
        &self, dumper: &mut DUMPER,
    ) -> Result<()> {
        let inserter = DeltaMptInserter {
            maybe_mpt: Some(self.delta_trie.clone()),
            maybe_root_node: self.delta_trie_root.clone(),
        };

        inserter.iterate(dumper)
    }
}

use super::{
    super::{state::*, state_manager::*, storage_db::*},
    errors::*,
    multi_version_merkle_patricia_trie::{
        merkle_patricia_trie::{
            children_table::VanillaChildrenTable, cow_node_ref::KVInserter, *,
        },
        node_memory_manager::ActualSlabIndex,
        DeltaMpt, TrieProof,
    },
    owned_node_set::OwnedNodeSet,
    state_manager::*,
    state_proof::StateProof,
    storage_manager::DeltaMptInserter,
};
use crate::statedb::KeyPadding;
use parity_bytes::ToPretty;
use primitives::{
    EpochId, MerkleHash, StateRoot, StateRootAuxInfo, StateRootWithAuxInfo,
    MERKLE_NULL_NODE,
};
use std::{
    cell::UnsafeCell,
    collections::BTreeMap,
    hint::unreachable_unchecked,
    sync::{atomic::Ordering, Arc},
};
