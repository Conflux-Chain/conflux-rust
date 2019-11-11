// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod cache;
pub mod guarded_value;
pub(in super::super) mod merkle_patricia_trie;
pub(in super::super) mod node_memory_manager;
pub(super) mod node_ref_map;
pub(super) mod return_after_use;
pub(super) mod row_number;

/// Fork of upstream slab in order to compact data and be thread-safe without
/// giant lock.
mod slab;

pub use self::{
    node_memory_manager::{TrieNodeDeltaMpt, TrieNodeDeltaMptCell},
    node_ref_map::DEFAULT_NODE_MAP_SIZE,
};
pub use merkle_patricia_trie::trie_proof::TrieProof;

pub type DeltaMpt = MultiVersionMerklePatriciaTrie;

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
    /// These map are incomplete as some of other roots live in disk db.
    root_node_by_epoch: RwLock<HashMap<EpochId, NodeRefDeltaMpt>>,
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
    node_memory_manager: NodeMemoryManagerDeltaMpt,
    /// Underlying database for DeltaMpt.
    db: Arc<dyn DeltaDbTrait + Send + Sync>,
    /// The padding is uniquely generated for each DeltaMPT, and it's used to
    /// compute padding bytes for address and storage_key. The padding setup
    /// is against an attack where adversary artificially build deep paths in
    /// MPT.
    pub padding: KeyPadding,
    /// Take care of database clean-ups for DeltaMpt.
    // The variable is used in drop. Variable with non-trivial dtor shouldn't
    // trigger the compiler warning.
    #[allow(unused)]
    delta_mpts_releaser: DeltaDbReleaser,
    commit_lock: Mutex<AtomicCommit>,

    // This is a hack to avoid passing pivot chain information from consensus
    // to snapshot computation.
    // FIXME: do it from Consensus if possible.
    parent_epoch_by_epoch: RwLock<HashMap<EpochId, EpochId>>,
}

unsafe impl Sync for MultiVersionMerklePatriciaTrie {}

impl MultiVersionMerklePatriciaTrie {
    pub fn padding(
        snapshot_root: &MerkleHash, intermediate_delta_root: &MerkleHash,
    ) -> KeyPadding {
        let mut buffer = Vec::with_capacity(
            snapshot_root.0.len() + intermediate_delta_root.0.len(),
        );
        buffer.extend_from_slice(&snapshot_root.0);
        buffer.extend_from_slice(&intermediate_delta_root.0);
        keccak(&buffer).0
    }

    pub fn start_commit(
        &self,
    ) -> Result<AtomicCommitTransaction<Box<DeltaDbTransactionTraitObj>>> {
        Ok(AtomicCommitTransaction {
            info: self.commit_lock.lock(),
            transaction: self.db.start_transaction_dyn(true)?,
        })
    }

    pub fn new(
        kvdb: Arc<dyn DeltaDbTrait + Send + Sync>, conf: &StorageConfiguration,
        padding: KeyPadding, snapshot_epoch_id: EpochId,
        storage_manager: Arc<StorageManager>,
    ) -> Self
    {
        let row_number =
            Self::parse_row_number(kvdb.get("last_row_number".as_bytes()))
                // unwrap() on new is fine.
                .unwrap()
                .unwrap_or_default();

        Self {
            root_node_by_epoch: Default::default(),
            root_node_by_merkle_root: Default::default(),
            node_memory_manager: NodeMemoryManagerDeltaMpt::new(
                conf.cache_start_size,
                conf.cache_size,
                conf.idle_size,
                conf.node_map_size,
                LRU::<RLFUPosT, DeltaMptDbKey>::new(conf.cache_size),
            ),
            padding,
            delta_mpts_releaser: DeltaDbReleaser {
                snapshot_epoch_id,
                storage_manager: Arc::downgrade(&storage_manager),
            },
            db: kvdb,
            commit_lock: Mutex::new(AtomicCommit {
                row_number: RowNumber { value: row_number },
            }),
            parent_epoch_by_epoch: Default::default(),
        }
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
    ) -> Result<Option<NodeRefDeltaMpt>> {
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
            None => Ok(None),
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
    ) -> Result<Option<NodeRefDeltaMpt>> {
        let node_ref = self.root_node_by_epoch.read().get(epoch_id).cloned();
        if node_ref.is_none() {
            self.load_root_node_ref_from_db_by_epoch(epoch_id)
        } else {
            Ok(node_ref)
        }
    }

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
    pub(super) fn set_epoch_root(
        &self, epoch_id: EpochId, root: NodeRefDeltaMpt,
    ) {
        self.root_node_by_epoch.write().insert(epoch_id, root);
    }

    pub(super) fn set_root_node_ref(
        &self, merkle_root: MerkleHash, node_ref: NodeRefDeltaMpt,
    ) {
        self.root_node_by_merkle_root
            .write()
            .insert(merkle_root, node_ref);
    }

    pub(super) fn set_parent_epoch(
        &self, parent_epoch_id: EpochId, epoch_id: EpochId,
    ) {
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
    ) -> NodeRefDeltaMpt {
        let root = NodeRefDeltaMpt::Committed { db_key };
        self.set_epoch_root(*epoch_id, root.clone());

        root
    }

    pub fn get_node_memory_manager(&self) -> &NodeMemoryManagerDeltaMpt {
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
                        &mut false,
                    )?
                    .get_merkle()
                    .clone(),
            )),
            None => Ok(None),
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

use self::{
    cache::algorithm::lru::LRU, merkle_patricia_trie::*,
    node_memory_manager::*, node_ref_map::DeltaMptDbKey, row_number::*,
};
use super::{
    super::storage_db::delta_db_manager::{
        DeltaDbOwnedReadTraitObj, DeltaDbTrait, DeltaDbTransactionTraitObj,
    },
    errors::*,
    storage_manager::storage_manager::*,
};
use crate::{
    statedb::KeyPadding, storage::state_manager::StorageConfiguration,
};
use cfx_types::hexstr_to_h256;
use keccak_hash::keccak;
use parking_lot::{Mutex, MutexGuard, RwLock};
use primitives::{EpochId, MerkleHash};
use std::{any::Any, borrow::BorrowMut, collections::HashMap, sync::Arc};
