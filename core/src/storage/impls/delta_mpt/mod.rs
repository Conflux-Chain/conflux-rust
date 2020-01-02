// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod cache;
pub mod cache_manager_delta_mpts;
pub mod cow_node_ref;
pub mod delta_mpt_iterator;
mod mem_optimized_trie_node;
pub(in super::super) mod node_memory_manager;
mod node_ref;
pub(super) mod node_ref_map;
pub(super) mod owned_node_set;
pub(super) mod return_after_use;
pub(super) mod row_number;
/// Fork of upstream slab in order to compact data and be thread-safe without
/// giant lock.
mod slab;
pub mod subtrie_visitor;

#[cfg(test)]
mod tests;

pub use self::{
    cow_node_ref::CowNodeRef,
    delta_mpt_iterator::DeltaMptIterator,
    mem_optimized_trie_node::MemOptimizedTrieNode,
    node_memory_manager::{TrieNodeDeltaMpt, TrieNodeDeltaMptCell},
    node_ref::*,
    node_ref_map::DEFAULT_NODE_MAP_SIZE,
    owned_node_set::OwnedNodeSet,
    subtrie_visitor::SubTrieVisitor,
};

pub type DeltaMpt = MultiVersionMerklePatriciaTrie;

pub type ChildrenTableDeltaMpt = CompactedChildrenTable<NodeRefDeltaMptCompact>;
pub type ChildrenTableManagedDeltaMpt = ChildrenTable<NodeRefDeltaMptCompact>;

#[derive(Default)]
pub struct AtomicCommit {
    pub row_number: RowNumber,
}

pub struct AtomicCommitTransaction<
    'a,
    Transaction: BorrowMut<DeltaDbTransactionTraitObj>,
> {
    pub info: MutexGuard<'a, AtomicCommit>,
    pub transaction: Transaction,
}

pub struct MultiVersionMerklePatriciaTrie {
    /// Id for cache manager.
    mpt_id: DeltaMptId,
    /// These map are incomplete as some of other roots live in disk db.
    root_node_by_epoch: RwLock<HashMap<EpochId, Option<NodeRefDeltaMpt>>>,
    /// Find trie root by merkle root is mainly for debugging.
    root_node_by_merkle_root: RwLock<HashMap<MerkleHash, NodeRefDeltaMpt>>,
    /// Note that we don't manage ChildrenTable in allocator because it's
    /// variable-length.
    ///
    /// The node memory manager holds reference to db on disk which stores MPT
    /// nodes.
    ///
    /// The nodes in memory should be considered a cache for MPT.
    /// However for delta_trie the disk_db contains MPT nodes which are swapped
    /// out from memory because persistence isn't necessary.
    /// (So far we don't have write-back implementation. For write-back we
    /// should think more about roots in disk db.)
    node_memory_manager: Arc<DeltaMptsNodeMemoryManager>,
    /// Underlying database for DeltaMpt.
    db: Arc<dyn DeltaDbTrait + Send + Sync>,
    /// Take care of database clean-ups for DeltaMpt.
    // The variable is used in drop. Variable with non-trivial dtor shouldn't
    // trigger the compiler warning.
    #[allow(unused)]
    delta_mpts_releaser: DeltaDbReleaser,
    /// Mutex for row number computation in state commitment.
    commit_lock: Mutex<AtomicCommit>,

    // This is a hack to avoid passing pivot chain information from consensus
    // to snapshot computation.
    // FIXME: do it from Consensus if possible.
    parent_epoch_by_epoch: RwLock<HashMap<EpochId, EpochId>>,
}

impl MultiVersionMerklePatriciaTrie {
    pub fn new(
        kvdb: Arc<dyn DeltaDbTrait + Send + Sync>, snapshot_epoch_id: EpochId,
        storage_manager: Arc<StorageManager>,
        delta_mpt_id_gen: &mut DeltaMptIdGen,
        node_memory_manager: Arc<DeltaMptsNodeMemoryManager>,
    ) -> Result<Self>
    {
        let row_number =
            Self::parse_row_number(kvdb.get("last_row_number".as_bytes()))
                // unwrap() on new is fine.
                .unwrap()
                .unwrap_or_default();
        let mpt_id = delta_mpt_id_gen.allocate()?;

        debug!("Created DeltaMpt with id {}", mpt_id);

        Ok(Self {
            mpt_id,
            root_node_by_epoch: Default::default(),
            root_node_by_merkle_root: Default::default(),
            node_memory_manager,
            delta_mpts_releaser: DeltaDbReleaser {
                snapshot_epoch_id,
                storage_manager: Arc::downgrade(&storage_manager),
                mpt_id,
            },
            db: kvdb,
            commit_lock: Mutex::new(AtomicCommit {
                row_number: RowNumber { value: row_number },
            }),
            parent_epoch_by_epoch: Default::default(),
        })
    }

    pub fn get_mpt_id(&self) -> DeltaMptId { self.mpt_id }

    pub fn start_commit(
        &self,
    ) -> Result<AtomicCommitTransaction<Box<DeltaDbTransactionTraitObj>>> {
        Ok(AtomicCommitTransaction {
            info: self.commit_lock.lock(),
            transaction: self.db.start_transaction_dyn(true)?,
        })
    }

    pub(super) fn state_root_committed(
        &self, epoch_id: EpochId, merkle_root: &MerkleHash,
        parent_epoch_id: EpochId, root_node: Option<NodeRefDeltaMpt>,
    )
    {
        self.set_parent_epoch(epoch_id, parent_epoch_id.clone());
        if root_node.is_some() {
            self.set_root_node_ref(
                merkle_root.clone(),
                root_node.clone().unwrap(),
            );
        }
        self.set_epoch_root(epoch_id, root_node);
    }

    fn load_root_node_ref_from_db(
        &self, merkle_root: &MerkleHash,
    ) -> Result<Option<NodeRefDeltaMpt>> {
        let db_key_result = Self::parse_row_number(
            // FIXME: the usage here for sqlite is serialized.
            // FIXME: Think of a way of doing it correctly.
            //
            // FIXME: think about operations in state_manager and state, which
            // FIXME: deserve a dedicated db connection. (Of course read-only)
            self.db.get(
                ["db_key_for_root_".as_bytes(), merkle_root.as_ref()]
                    .concat()
                    .as_slice(),
            ),
        )?;
        match db_key_result {
            Some(db_key) => Ok(Some(self.loaded_root(merkle_root, db_key))),
            None => Ok(None),
        }
    }

    fn load_root_node_ref_from_db_by_epoch(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Option<NodeRefDeltaMpt>>> {
        let db_key_result = Self::parse_row_number(
            // FIXME: the usage here for sqlite is serialized.
            // FIXME: Think of a way of doing it correctly.
            //
            // FIXME: think about operations in state_manager and state, which
            // FIXME: deserve a dedicated db connection. (Of course read-only)
            self.db.get(
                ["db_key_for_epoch_id_".as_bytes(), epoch_id.as_ref()]
                    .concat()
                    .as_slice(),
            ),
        )?;
        match db_key_result {
            Some(db_key) => {
                Ok(Some(self.loaded_root_at_epoch(epoch_id, db_key)))
            }
            None => {
                if self.get_parent_epoch(epoch_id)?.is_some() {
                    Ok(Some(None))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn load_parent_epoch_id_from_db(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<EpochId>> {
        let parent_epoch_id_result =
            // FIXME: the usage here for sqlite is serialized.
            // FIXME: Think of a way of doing it correctly.
            //
            // FIXME: think about operations in state_manager and state, which
            // FIXME: deserve a dedicated db connection. (Of course read-only)
            self.db.get(
                ["parent_epoch_id_".as_bytes(), epoch_id.as_ref()]
                    .concat()
                    .as_slice(),
            )?;
        match parent_epoch_id_result {
            Some(parent_epoch_id_hexstr) => {
                let parent_epoch_id = hexstr_to_h256(unsafe {
                    std::str::from_utf8_unchecked(&*parent_epoch_id_hexstr)
                });
                self.set_parent_epoch(
                    epoch_id.clone(),
                    parent_epoch_id.clone(),
                );
                Ok(Some(parent_epoch_id))
            }
            None => Ok(None),
        }
    }

    pub fn get_root_node_ref_by_epoch(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Option<NodeRefDeltaMpt>>> {
        let node_ref = self.root_node_by_epoch.read().get(epoch_id).cloned();
        if node_ref.is_none() {
            self.load_root_node_ref_from_db_by_epoch(epoch_id)
        } else {
            Ok(node_ref)
        }
    }

    /// Find trie root by merkle root is mainly for debugging.
    pub fn get_root_node_ref(
        &self, merkle_root: &MerkleHash,
    ) -> Result<Option<NodeRefDeltaMpt>> {
        let node_ref = self
            .root_node_by_merkle_root
            .read()
            .get(merkle_root)
            .cloned();
        if node_ref.is_none() {
            self.load_root_node_ref_from_db(merkle_root)
        } else {
            Ok(node_ref)
        }
    }

    pub fn get_parent_epoch(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<EpochId>> {
        let parent_epoch =
            self.parent_epoch_by_epoch.read().get(epoch_id).cloned();
        if parent_epoch.is_none() {
            self.load_parent_epoch_id_from_db(epoch_id)
        } else {
            Ok(parent_epoch)
        }
    }

    // These set methods are private to storage mod. Writing to db happens at
    // state commitment.
    fn set_epoch_root(&self, epoch_id: EpochId, root: Option<NodeRefDeltaMpt>) {
        self.root_node_by_epoch.write().insert(epoch_id, root);
    }

    fn set_root_node_ref(
        &self, merkle_root: MerkleHash, node_ref: NodeRefDeltaMpt,
    ) {
        self.root_node_by_merkle_root
            .write()
            .insert(merkle_root, node_ref);
    }

    fn set_parent_epoch(&self, epoch_id: EpochId, parent_epoch_id: EpochId) {
        self.parent_epoch_by_epoch
            .write()
            .insert(epoch_id, parent_epoch_id);
    }

    fn loaded_root(
        &self, merkle_root: &MerkleHash, db_key: DeltaMptDbKey,
    ) -> NodeRefDeltaMpt {
        let root = NodeRefDeltaMpt::Committed { db_key };
        self.set_root_node_ref(*merkle_root, root.clone());

        root
    }

    fn loaded_root_at_epoch(
        &self, epoch_id: &EpochId, db_key: DeltaMptDbKey,
    ) -> Option<NodeRefDeltaMpt> {
        let root = Some(NodeRefDeltaMpt::Committed { db_key });
        self.set_epoch_root(*epoch_id, root.clone());

        root
    }

    pub fn get_node_memory_manager(&self) -> &DeltaMptsNodeMemoryManager {
        &self.node_memory_manager
    }

    pub fn get_merkle(
        &self, maybe_node: Option<NodeRefDeltaMpt>,
    ) -> Result<Option<MerkleHash>> {
        match maybe_node {
            Some(node) => Ok(Some(
                self.node_memory_manager
                    .node_as_ref_with_cache_manager(
                        &self.node_memory_manager.get_allocator(),
                        node,
                        self.node_memory_manager.get_cache_manager(),
                        &mut *self.db.to_owned_read()?,
                        self.mpt_id,
                        &mut false,
                    )?
                    .get_merkle()
                    .clone(),
            )),
            None => Ok(None),
        }
    }

    pub fn get_merkle_root_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<MerkleHash>> {
        match self.get_root_node_ref_by_epoch(epoch_id)? {
            None => Ok(None),
            Some(root_node) => {
                Ok(self.get_merkle(root_node)?.or(Some(MERKLE_NULL_NODE)))
            }
        }
    }

    pub fn log_usage(&self) { self.node_memory_manager.log_usage(); }
}

// Utility function.
impl MultiVersionMerklePatriciaTrie {
    fn parse_row_number(
        x: Result<Option<Box<[u8]>>>,
    ) -> Result<Option<RowNumberUnderlyingType>> {
        Ok(match x?.as_ref() {
            None => None,
            Some(row_number_bytes) => Some(
                unsafe {
                    std::str::from_utf8_unchecked(row_number_bytes.as_ref())
                }
                .parse::<RowNumberUnderlyingType>()?,
            ),
        })
    }

    pub fn db_owned_read<'a>(
        &'a self,
    ) -> Result<Box<DeltaDbOwnedReadTraitObj<'a>>> {
        self.db.to_owned_read()
    }

    pub fn db_commit(&self) -> &dyn Any { (*self.db).as_any() }
}

#[derive(Default)]
pub struct DeltaMptIdGen {
    id_limit: DeltaMptId,
    available_ids: Vec<DeltaMptId>,
}

impl DeltaMptIdGen {
    pub fn allocate(&mut self) -> Result<DeltaMptId> {
        let id;
        match self.available_ids.pop() {
            None => {
                if self.id_limit != DeltaMptId::max_value() {
                    id = Ok(self.id_limit);
                    self.id_limit += 1;
                } else {
                    id = Err(ErrorKind::TooManyDeltaMPT.into())
                }
            }
            Some(x) => id = Ok(x),
        };

        id
    }

    pub fn free(&mut self, id: DeltaMptId) {
        let max_id = self.id_limit - 1;
        if id == max_id {
            self.id_limit = max_id
        } else {
            self.available_ids.push(id);
        }
    }
}

use self::{
    node_memory_manager::*, node_ref_map::DeltaMptDbKey, row_number::*,
};
use crate::storage::{
    impls::{
        delta_mpt::node_ref_map::DeltaMptId, errors::*,
        merkle_patricia_trie::*, storage_manager::storage_manager::*,
    },
    storage_db::delta_db_manager::{
        DeltaDbOwnedReadTraitObj, DeltaDbTrait, DeltaDbTransactionTraitObj,
    },
};
use cfx_types::hexstr_to_h256;
use parking_lot::{Mutex, MutexGuard, RwLock};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE};
use std::{any::Any, borrow::BorrowMut, collections::HashMap, sync::Arc};
