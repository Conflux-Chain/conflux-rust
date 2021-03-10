// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, MallocSizeOfDerive)]
pub enum TrieCacheSlotOrCacheAlgoData<CacheAlgoDataT: CacheAlgoDataTrait> {
    TrieCacheSlot(ActualSlabIndex),
    CacheAlgoData(CacheAlgoDataT),
}

// TODO(yz): Rename class and explain how this class interact with the lifecycle
// of trie node.
/// CacheableNodeRef maintains the information of cached node and possibly
/// non-cached children of cached node.
///
/// Only CacheableNodeRef for Delta MPT is currently implemented.
///
/// CacheableNodeRef for persistent MPT may add a field for storage access key,
/// and a reference count. For persistent MPT, NodeRef (storage access key) for
/// non-cached node might be kept, to be able to read child node directly from
/// disk, otherwise the program have to read the current node again to first
/// obtain the CacheableNodeRef for the non-cached child node. However a
/// reference count is necessary to prevent NodeRef for non-cached node from
/// staying forever in the memory.
#[derive(Clone, MallocSizeOfDerive)]
pub struct CacheableNodeRefDeltaMpt<CacheAlgoDataT: CacheAlgoDataTrait> {
    cached: TrieCacheSlotOrCacheAlgoData<CacheAlgoDataT>,
}

impl<CacheAlgoDataT: CacheAlgoDataTrait>
    CacheableNodeRefDeltaMpt<CacheAlgoDataT>
{
    pub fn new(cached: TrieCacheSlotOrCacheAlgoData<CacheAlgoDataT>) -> Self {
        Self { cached }
    }

    pub fn get_cache_info(
        &self,
    ) -> &TrieCacheSlotOrCacheAlgoData<CacheAlgoDataT> {
        &self.cached
    }

    pub fn get_slot(&self) -> Option<&ActualSlabIndex> {
        match &self.cached {
            TrieCacheSlotOrCacheAlgoData::CacheAlgoData(_) => None,
            TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot) => Some(slot),
        }
    }
}

/// Generally, the db key of MPT node is the merkle hash, however it consumes
/// too much memory. For Delta MPT, the total number of nodes at 1000tps are
/// relative small compared to memory consumed by Cached TrieNodes, and we don't
/// need to persist, therefore we could use "row number" as db key.
pub type DeltaMptDbKey = RowNumberUnderlyingType;
// Each DeltaMpt is assigned an index. There are not many DeltaMpts to keep at a
// time.
pub type DeltaMptId = u16;
const MPT_ID_RANGE: usize = std::u16::MAX as usize + 1;

// TODO(yz): Optimize the access like NodeRefMapDeltaMpt. Keep a number of
// TODO(yz): chunks, each delta mpt maintains a deque of chunks. Whenever all
// TODO(yz): chunks are filled, reclaim one chunk from the mpt with the lowest
// TODO(yz): chunk cached rate.
/// Maintains the cache slot / cache info for multiple Delta MPTs.
#[derive(MallocSizeOfDerive)]
pub struct NodeRefMapDeltaMpts<CacheAlgoDataT: CacheAlgoDataTrait> {
    node_ref_maps:
        Vec<HashMap<DeltaMptDbKey, CacheableNodeRefDeltaMpt<CacheAlgoDataT>>>,
    nodes: usize,
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> NodeRefMapDeltaMpts<CacheAlgoDataT> {
    pub fn new() -> Self {
        let mut node_ref_maps = Vec::with_capacity(MPT_ID_RANGE);
        for _i in 0..MPT_ID_RANGE {
            node_ref_maps.push(Default::default());
        }

        Self {
            node_ref_maps,
            nodes: 0,
        }
    }

    /// Insert may crash due to memory allocation issue, although it won't
    /// return error in current implementation.
    pub fn insert(
        &mut self, key: (DeltaMptId, DeltaMptDbKey), slot: ActualSlabIndex,
    ) -> Result<()> {
        if self.node_ref_maps[key.0 as usize]
            .insert(
                key.1,
                CacheableNodeRefDeltaMpt {
                    cached: TrieCacheSlotOrCacheAlgoData::TrieCacheSlot(slot),
                },
            )
            .is_none()
        {
            self.nodes += 1;
        };
        Ok(())
    }

    /// The cache_info is only valid when the element still lives in cache.
    /// Therefore we return the reference to the cache_info to represent the
    /// lifetime requirement.
    pub fn get_cache_info(
        &self, key: (DeltaMptId, DeltaMptDbKey),
    ) -> Option<&CacheableNodeRefDeltaMpt<CacheAlgoDataT>> {
        self.node_ref_maps[key.0 as usize].get(&key.1)
    }

    pub fn set_cache_info(
        &mut self, key: (DeltaMptId, DeltaMptDbKey),
        cache_info: CacheableNodeRefDeltaMpt<CacheAlgoDataT>,
    )
    {
        if self.node_ref_maps[key.0 as usize]
            .insert(key.1, cache_info)
            .is_none()
        {
            self.nodes += 1;
        }
    }

    pub fn delete(
        &mut self, key: (DeltaMptId, DeltaMptDbKey),
    ) -> Option<CacheableNodeRefDeltaMpt<CacheAlgoDataT>> {
        let maybe_old_value = self.node_ref_maps[key.0 as usize].remove(&key.1);
        if maybe_old_value.is_some() {
            self.nodes -= 1;
        }
        maybe_old_value
    }

    pub fn get_all_cache_infos_from_mpt(
        &self, mpt_id: DeltaMptId,
    ) -> Vec<(DeltaMptDbKey, CacheableNodeRefDeltaMpt<CacheAlgoDataT>)> {
        self.node_ref_maps[mpt_id as usize]
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn log_usage(&self) {
        debug!("node_ref_map.BTreeMap: #nodes: {}", self.nodes,);
    }
}

pub const DEFAULT_NODE_MAP_SIZE: DeltaMptDbKey = 200_000_000;

// Type alias for clarity.
pub trait NodeRefMapTrait {
    type StorageAccessKey;
    type NodeRef;
    type MaybeCacheSlotIndex;
}

use super::{
    super::errors::*, cache::algorithm::CacheAlgoDataTrait,
    node_memory_manager::ActualSlabIndex, row_number::RowNumberUnderlyingType,
};
use hashbrown::HashMap;
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
