// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod cache;
pub(in super::super) mod merkle_patricia_trie;
pub(in super::super) mod node_memory_manager;
pub(super) mod return_after_use;
pub(super) mod row_number;

pub use self::node_ref_map::DEFAULT_NODE_MAP_SIZE;

pub struct MultiVersionMerklePatriciaTrie {
    /// We don't distinguish an epoch which doesn't exists from an epoch which
    /// contains nothing.
    /// This version map is incomplete as the rest map lives in disk db.
    root_by_version: RwLock<HashMap<EpochId, NodeRefDeltaMpt>>,
    /// The nodes in memory should be considered a cache for MPT.
    /// However for delta_trie the disk_db contains MPT nodes which are swapped
    /// out from memory because persistence isn't necessary.
    ///
    /// Note that we don't manage ChildrenTable in allocator because it's
    /// variable-length.
    ///
    /// The node memory manager holds reference to db on disk which stores MPT
    /// nodes.
    node_memory_manager: NodeMemoryManagerDeltaMpt,
}

impl MultiVersionMerklePatriciaTrie {
    pub fn new(kvdb: Arc<KeyValueDB>, conf: StorageConfiguration) -> Self {
        Self {
            root_by_version: Default::default(),
            node_memory_manager: NodeMemoryManagerDeltaMpt::new(
                conf.cache_start_size,
                conf.cache_size,
                conf.idle_size,
                conf.node_map_size,
                RecentLFU::<RLFUPosT, DeltaMptDbKey>::new(
                    conf.cache_size,
                    (conf.cache_size as f64 * conf.recent_lfu_factor) as u32,
                ),
                kvdb,
            ),
        }
    }

    pub fn get_root_at_epoch(
        &self, epoch_id: EpochId,
    ) -> Option<NodeRefDeltaMpt> {
        self.root_by_version.read().get(&epoch_id).cloned()
    }

    pub fn set_epoch_root(&self, epoch_id: EpochId, root: NodeRefDeltaMpt) {
        self.root_by_version.write().insert(epoch_id, root);
    }

    pub fn loaded_root_at_epoch(
        &self, epoch_id: EpochId, db_key: DeltaMptDbKey,
    ) -> NodeRefDeltaMpt {
        let root = NodeRefDeltaMpt::Committed { db_key: db_key };
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

mod guarded_value;
pub(self) mod node_ref_map;
/// Fork of upstream slab in order to compact data and to provide internal
/// mutability.
mod slab;

use self::{
    cache::algorithm::recent_lfu::RecentLFU, merkle_patricia_trie::*,
    node_memory_manager::*, node_ref_map::DeltaMptDbKey,
};
use super::errors::*;
use crate::storage::state_manager::StorageConfiguration;
use kvdb::KeyValueDB;
use parking_lot::RwLock;
use primitives::EpochId;
use std::{collections::HashMap, sync::Arc};
