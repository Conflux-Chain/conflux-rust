// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub(super) mod errors;
pub(super) mod multi_version_merkle_patricia_trie;
pub(super) mod state;
pub(super) mod state_manager;
pub(super) mod state_proof;
pub(super) mod storage_db;
// FIXME: scope
pub(super) mod storage_manager;

pub mod defaults {
    pub use super::multi_version_merkle_patricia_trie::DEFAULT_NODE_MAP_SIZE;
    pub const DEFAULT_CACHE_SIZE: u32 =
        NodeMemoryManagerDeltaMpt::MAX_CACHED_TRIE_NODES_DISK_HYBRID;
    pub const DEFAULT_CACHE_START_SIZE: u32 =
        NodeMemoryManagerDeltaMpt::START_CAPACITY;
    pub const DEFAULT_RECENT_LFU_FACTOR: f64 =
        NodeMemoryManagerDeltaMpt::R_LFU_FACTOR;
    pub const DEFAULT_IDLE_SIZE: u32 =
        NodeMemoryManagerDeltaMpt::MAX_DIRTY_AND_TEMPORARY_TRIE_NODES;
    pub const MAX_CACHED_TRIE_NODES_R_LFU_COUNTER: u32 =
        NodeMemoryManagerDeltaMpt::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER;

    use super::multi_version_merkle_patricia_trie::node_memory_manager::NodeMemoryManagerDeltaMpt;
}
