// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type OwnedNodeSet = BTreeSet<NodeRefDeltaMpt>;

pub struct State<'a> {
    manager: &'a StateManager,
    delta_trie: &'a MultiVersionMerklePatriciaTrie,
    root_node: Option<NodeRefDeltaMpt>,
    owned_node_set: Option<OwnedNodeSet>,
    dirty: bool,
}

impl<'a> State<'a> {
    pub fn new(
        manager: &'a StateManager, root_node: Option<NodeRefDeltaMpt>,
    ) -> Self {
        Self {
            manager: manager,
            delta_trie: manager.get_delta_trie(),
            root_node: root_node.clone(),
            owned_node_set: Some(Default::default()),
            dirty: false,
        }
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
    fn does_exist(&self) -> bool { self.get_root_node().is_some() }

    fn get_merkle_hash(&self, access_key: &[u8]) -> Result<Option<MerkleHash>> {
        // Get won't create any new nodes so it's fine to pass an empty
        // owned_node_set.
        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());
        match self.get_root_node() {
            None => Ok(None),
            Some(root_node) => SubTrieVisitor::new(
                self.delta_trie,
                root_node,
                &mut empty_owned_node_set,
            )
            .get_merkle_hash_wo_compressed_path(access_key),
        }
    }

    fn get(&self, access_key: &[u8]) -> Result<Option<Box<[u8]>>> {
        // Get won't create any new nodes so it's fine to pass an empty
        // owned_node_set.
        let mut empty_owned_node_set: Option<OwnedNodeSet> =
            Some(Default::default());
        let maybe_root_node = self.get_root_node();
        match maybe_root_node {
            None => Ok(None),
            Some(root_node) => SubTrieVisitor::new(
                self.delta_trie,
                root_node,
                &mut empty_owned_node_set,
            )
            .get(access_key),
        }
    }

    fn set(&mut self, access_key: &[u8], value: &[u8]) -> Result<()> {
        self.pre_modification();

        self.root_node = SubTrieVisitor::new(
            self.delta_trie,
            self.get_or_create_root_node()?,
            &mut self.owned_node_set,
        )
        .set(access_key, value)?
        .into();

        Ok(())
    }

    fn delete(&mut self, access_key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.pre_modification();

        match self.get_root_node() {
            None => Ok(None),
            Some(old_root_node) => {
                let (old_value, _, root_node) = SubTrieVisitor::new(
                    self.delta_trie,
                    old_root_node,
                    &mut self.owned_node_set,
                )
                .delete(access_key)?;
                self.root_node = root_node.map(|maybe_node| maybe_node.into());
                Ok(old_value)
            }
        }
    }

    fn delete_all(
        &mut self, access_key_prefix: &[u8],
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>> {
        self.pre_modification();

        match self.get_root_node() {
            None => Ok(None),
            Some(old_root_node) => {
                let (deleted, _, root_node) = SubTrieVisitor::new(
                    self.delta_trie,
                    old_root_node,
                    &mut self.owned_node_set,
                )
                .delete_all(access_key_prefix, access_key_prefix)?;
                self.root_node = root_node.map(|maybe_node| maybe_node.into());
                Ok(deleted)
            }
        }
    }

    fn compute_state_root(&mut self) -> Result<MerkleHash> {
        self.compute_merkle_root()
    }

    fn get_state_root(&self) -> Result<Option<MerkleHash>> {
        self.delta_trie.get_merkle(self.root_node.clone())
    }

    // TODO(yz): replace coarse lock with a queue.
    fn commit(&mut self, epoch_id: EpochId) -> Result<()> {
        self.state_root_check()?;

        // TODO(yz): Think about leaving these node dirty and only commit when
        // the dirty node is removed from cache.
        let commit_result = self.do_db_commit(epoch_id);
        if commit_result.is_err() {
            self.revert();
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

    // FIXME: move to merkle_patricia_trie mod
    fn get_root_node(&self) -> Option<NodeRefDeltaMpt> {
        self.root_node.clone()
    }

    fn get_or_create_root_node(&mut self) -> Result<NodeRefDeltaMpt> {
        if self.root_node.is_none() {
            let allocator =
                self.delta_trie.get_node_memory_manager().get_allocator();
            let (root_cow, entry) = CowNodeRef::new_uninitialized_node(
                &allocator,
                self.owned_node_set.as_mut().unwrap(),
            )?;
            // Insert empty node.
            entry.insert(Default::default());

            self.root_node =
                root_cow.into_child().map(|maybe_node| maybe_node.into());
        }

        // Safe because in either branch the result is Some.
        Ok(self.get_root_node().unwrap())
    }

    fn compute_merkle_root(&mut self) -> Result<MerkleHash> {
        match &self.root_node {
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
                    self.delta_trie,
                    self.owned_node_set.as_mut().unwrap(),
                    &allocator,
                )?;
                cow_root.into_child();

                Ok(merkle)
            }
        }
    }

    fn do_db_commit(&mut self, epoch_id: EpochId) -> Result<()> {
        // TODO(yz): accumulate to db write counter.
        self.dirty = false;

        let maybe_root_node = self.root_node.clone();
        match maybe_root_node {
            None => {
                // Don't commit empty state. Empty state shouldn't exists after
                // genesis block.
            }
            Some(root_node) => {
                // Use coarse lock to prevent row number from interleaving,
                // which makes it cleaner to restart from db failure. It also
                // benefits performance because without a coarse lock all
                // threads may not be able to do anything else when they compete
                // with each other on slow db writing.
                let mut commit_transaction = self.manager.start_commit();
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
                        self.delta_trie,
                        self.owned_node_set.as_mut().unwrap(),
                        trie_node_mut,
                        &mut commit_transaction,
                        &mut *self
                            .delta_trie
                            .get_node_memory_manager()
                            .get_cache_manager()
                            .lock(),
                        &allocator,
                    );
                    self.root_node = cow_root.into_child().map(|r| r.into());
                    result?;

                    commit_transaction.transaction.put(
                        COL_DELTA_TRIE,
                        "last_row_number".as_bytes(),
                        commit_transaction
                            .info
                            .row_number
                            .to_string()
                            .as_bytes(),
                    );
                }

                let db_key = *{
                    match self.root_node.as_ref().unwrap() {
                        // Dirty state are committed.
                        NodeRefDeltaMpt::Dirty { index } => unsafe {
                            unreachable_unchecked();
                        },
                        // Empty block's state root points to its base state.
                        NodeRefDeltaMpt::Committed { db_key } => db_key,
                    }
                };

                commit_transaction.transaction.put(
                    COL_DELTA_TRIE,
                    [
                        "state_root_db_key_for_epoch_id_".as_bytes(),
                        epoch_id.as_ref(),
                    ]
                    .concat()
                    .as_slice(),
                    db_key.to_string().as_bytes(),
                );

                self.manager
                    .db
                    .key_value()
                    .write(commit_transaction.transaction)?;

                self.manager.number_commited_nodes.fetch_add(
                    (commit_transaction.info.row_number.value
                        - start_row_number) as usize,
                    Ordering::Relaxed,
                );

                self.manager
                    .mpt_commit_state_root(epoch_id, self.root_node.clone());
            }
        }

        Ok(())
    }

    fn state_root_check(&self) -> Result<()> {
        let maybe_merkle_hash = self.get_merkle_hash(&[])?;
        match maybe_merkle_hash {
            // Empty state.
            None => (Ok(())),
            Some(merkle_hash) => {
                // Non-empty state
                if merkle_hash.is_zero() {
                    Err(ErrorKind::StateCommitWithoutMerkleHash.into())
                } else {
                    Ok(())
                }
            }
        }
    }
}

use super::{
    super::{super::db::COL_DELTA_TRIE, state::*, state_manager::*},
    errors::*,
    multi_version_merkle_patricia_trie::{
        merkle_patricia_trie::{merkle::MERKLE_NULL_NODE, *},
        MultiVersionMerklePatriciaTrie,
    },
};
use primitives::EpochId;
use std::{
    collections::BTreeSet, hint::unreachable_unchecked, sync::atomic::Ordering,
};
