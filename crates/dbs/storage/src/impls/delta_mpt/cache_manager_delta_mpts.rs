// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO: On performance, each access may requires a lock because of calling
// TODO: cache algorithm & cache eviction & TrieNode slab alloc/delete
// TODO: & noderefmap update. The read & write can not be easily broken
// TODO: down because of dependency. Calling cache algorithm always
// TODO: requires write lock to algorithm. cache hit updates can be
// TODO: batched locally. The caller knows whether a node is hit. But the
// TODO: element for batched hit update could be evicted by other threads. cache
// TODO: miss locks mutably for slab alloc/delete, noderefmap update.
// TODO: can also be batched however the lifetime of TrieNode should be managed.
#[derive(MallocSizeOfDerive)]
pub struct CacheManagerDeltaMpts<
    CacheAlgoDataT: CacheAlgoDataTrait,
    CacheAlgorithmT: CacheAlgorithm<CacheAlgoData = CacheAlgoDataT>,
> {
    /// One of the key problem in implementing a cache for tree node is that,
    /// when a node is swapped-out from cache into disk, the eviction of
    /// children should be independent, not only because of cache hit
    /// property, but also because that a node can have multiple parents. When
    /// a node is loaded into cache again, it should automatically connects
    /// to its children in cache, even if the children is shared with some
    /// other node unknown.
    ///
    /// Another problem is that, when a node is swapped-out, the parent's
    /// children reference must be updated unless the children reference is
    /// the db key, or something stable. The db key in Conflux is the
    /// Merkle Hash, which is too large for a Trie node: 16*64B are
    /// required to store only ChildrenTable.
    ///
    /// To solve these problems, we introduce CacheableNodeRef, which should
    /// remain stable for the lifetime of the TrieNode of the
    /// ChildrenTable. The key of NodeRefMap shall be db key, and the value
    /// of NodeRefMap shall point to where the node is cached.
    ///
    /// The db key could be made smaller for Delta MPT (4B)
    /// and maybe for Persistent MPT (8B) by simply using the row number.
    ///
    /// If we have to use Merkle Hash (64B) as db key for Persistent MPT,
    /// storing the key for non-cached node is costly. There are two options,
    /// a) store key only for cached nodes, there is little addition cost (8B),
    /// however to load an un-cached child node from disk, caller should first
    /// read the child's access key by loading the current node, then check
    /// NodeRefMap, if actual missing load it from disk for the second
    /// time.
    /// b) create NodeRef for some children of cached node, store a the 64B key
    /// for disk access, and keep the reference count so that we don't store
    /// NodeRef for nodes which later becomes irrelevant indefinitely.
    ///
    /// Note that there are also dirty nodes, which always live in memory.
    /// The NodeRef / MaybeNodeRef also covers dirty nodes, but NodeRefMap
    /// covers only commited nodes.
    pub(super) node_ref_map: NodeRefMapDeltaMpts<CacheAlgoDataT>,
    pub(super) cache_algorithm: CacheAlgorithmT,
}

impl CacheIndexTrait for (DeltaMptId, DeltaMptDbKey) {}

impl<
        CacheAlgoDataT: CacheAlgoDataTrait,
        CacheAlgorithmT: CacheAlgorithm<
            CacheAlgoData = CacheAlgoDataT,
            CacheIndex = (DeltaMptId, DeltaMptDbKey),
        >,
    > CacheManagerDeltaMpts<CacheAlgoDataT, CacheAlgorithmT>
{
    pub fn insert_to_node_ref_map_and_call_cache_access(
        &mut self, cache_index: (DeltaMptId, DeltaMptDbKey),
        slot: ActualSlabIndex,
        node_memory_manager: &NodeMemoryManager<
            CacheAlgoDataT,
            CacheAlgorithmT,
        >,
    ) -> Result<()> {
        self.node_ref_map.insert(cache_index, slot)?;
        node_memory_manager.call_cache_algorithm_access(self, cache_index);
        Ok(())
    }

    pub fn is_cached(&self, cache_index: (DeltaMptId, DeltaMptDbKey)) -> bool {
        if let Some(cache_info) = self.node_ref_map.get_cache_info(cache_index)
        {
            cache_info.get_slot().is_some()
        } else {
            false
        }
    }

    pub fn log_usage(&self) {
        self.node_ref_map.log_usage();
        self.cache_algorithm.log_usage("trie node cache ");
    }
}

use super::{
    super::errors::*,
    cache::algorithm::{CacheAlgoDataTrait, CacheAlgorithm, CacheIndexTrait},
    node_memory_manager::{ActualSlabIndex, NodeMemoryManager},
    node_ref_map::{DeltaMptDbKey, DeltaMptId, NodeRefMapDeltaMpts},
};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
