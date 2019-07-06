// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod cache;
pub(in super::super) mod merkle_patricia_trie;
pub(in super::super) mod node_memory_manager;
pub(super) mod return_after_use;
pub(super) mod row_number;

pub use self::node_ref_map::DEFAULT_NODE_MAP_SIZE;

pub type DeltaMpt = MultiVersionMerklePatriciaTrie;

pub struct MultiVersionMerklePatriciaTrie {
    // TODO(yz): revisit the comment below. With snapshot we may have special
    // TODO(yz): api to create empty epoch.
    /// We don't distinguish an epoch which doesn't exists from an epoch which
    /// contains nothing.
    /// This version map is incomplete as some of other roots live in disk db.
    root_by_version: RwLock<HashMap<EpochId, NodeRefDeltaMpt>>,
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
    // TODO(yz): we should separate disk db from node_memory_manager because
    // TODO(yz): in different delta we don't share cache & db but we share
    // TODO(yz): memory.
    // FIXME: this is a big refactor. Add snapshot to storage manager first.
    node_memory_manager: NodeMemoryManagerDeltaMpt,
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
}

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

    pub fn new(
        kvdb: Arc<DeltaDbTrait + Send + Sync>, conf: StorageConfiguration,
        padding: KeyPadding, snapshot_root: MerkleHash,
        storage_manager: Arc<StorageManager>,
    ) -> Self
    {
        Self {
            root_by_version: Default::default(),
            node_memory_manager: NodeMemoryManagerDeltaMpt::new(
                conf.cache_start_size,
                conf.cache_size,
                conf.idle_size,
                conf.node_map_size,
                LRU::<RLFUPosT, DeltaMptDbKey>::new(conf.cache_size),
                kvdb,
            ),
            padding,
            delta_mpts_releaser: DeltaDbReleaser {
                snapshot_root,
                storage_manager,
            },
        }
    }

    // FIXME: implement the logic.
    pub fn should_shift_snapshot(&self) -> Result<bool> { Ok(false) }

    pub fn get_root_at_epoch(
        &self, epoch_id: &EpochId,
    ) -> Option<NodeRefDeltaMpt> {
        self.root_by_version.read().get(epoch_id).cloned()
    }

    pub fn set_epoch_root(&self, epoch_id: EpochId, root: NodeRefDeltaMpt) {
        self.root_by_version.write().insert(epoch_id, root);
    }

    pub fn loaded_root_at_epoch(
        &self, epoch_id: EpochId, db_key: DeltaMptDbKey,
    ) -> NodeRefDeltaMpt {
        let root = NodeRefDeltaMpt::Committed { db_key };
        self.set_epoch_root(epoch_id, root.clone());

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
                        &mut false,
                    )?
                    .merkle_hash,
            )),
            None => Ok(None),
        }
    }

    pub fn log_usage(&self) { self.node_memory_manager.log_usage(); }
}

pub mod guarded_value;
pub(self) mod node_ref_map;
/// Fork of upstream slab in order to compact data and to provide internal
/// mutability.
mod slab;

use self::{
    cache::algorithm::lru::LRU, merkle_patricia_trie::*,
    node_memory_manager::*, node_ref_map::DeltaMptDbKey,
};
use super::{
    super::storage_db::delta_db::DeltaDbTrait, errors::*,
    storage_manager::storage_manager::*,
};
use crate::{
    statedb::KeyPadding, storage::state_manager::StorageConfiguration,
};
use keccak_hash::keccak;
use parking_lot::RwLock;
use primitives::{EpochId, MerkleHash};
use std::{collections::HashMap, sync::Arc};
