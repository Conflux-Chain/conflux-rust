// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    lru::{LRUHandle, LRU},
    removable_heap::{HeapValueUtil, Hole, RemovableHeap},
    CacheAccessResult, CacheAlgoDataAdapter, CacheAlgoDataTrait,
    CacheAlgorithm, CacheIndexTrait, CacheStoreUtil, MyInto, PrimitiveNum,
};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{hint, mem};

/// In RecentLFU we keep an LRU to maintain frequency for alpha * cache_slots
/// recently visited elements. When inserting the most recent element, evict the
/// least recently used element from LRU (if necessary), then evict the
/// least frequent element from LFU (if necessary). The most recent element is
/// updated/inserted with frequency maintained in LRU. As long as an element
/// stays in LRU the frequency doesn't restart from 0.
///
/// The double link list algorithm for LFU can not extend if an element starts
/// from frequency greater than 0, and another downside is using much more
/// memory. We use heap to maintain frequency.
#[derive(MallocSizeOfDerive)]
pub struct RecentLFU<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> {
    capacity: PosT,
    frequency_lru: LRU<PosT, RecentLFUHandle<PosT>>,
    frequency_heap: RemovableHeap<PosT, RecentLFUMetadata<PosT, CacheIndexT>>,
    #[ignore_malloc_size_of = "insignificant"]
    counter_rng: ChaChaRng,
}

/// RecentLFUHandle points to the location where frequency data is stored. A
/// non-null pos means that the object is maintained in LRU.
#[derive(Clone, Copy, MallocSizeOfDerive)]
pub struct RecentLFUHandle<PosT: PrimitiveNum> {
    pos: PosT,
}

impl<PosT: PrimitiveNum> CacheAlgoDataTrait for RecentLFUHandle<PosT> {}

impl<PosT: PrimitiveNum> RecentLFUHandle<PosT> {
    const NULL_POS: i32 = -1;

    fn placement_new_handle(&mut self, pos: PosT) { self.set_handle(pos); }

    // The code is used by an currently unused class.
    #[allow(unused)]
    fn placement_new_evicted(&mut self) { self.set_evicted(); }

    pub fn is_lru_hit(&self) -> bool { self.pos != PosT::from(Self::NULL_POS) }

    fn is_lfu_hit<CacheIndexT: CacheIndexTrait>(
        &self, heap: &RemovableHeap<PosT, RecentLFUMetadata<PosT, CacheIndexT>>,
    ) -> bool {
        self.pos < heap.get_heap_size()
            && self.pos != PosT::from(Self::NULL_POS)
    }

    pub fn set_evicted(&mut self) { self.pos = PosT::from(Self::NULL_POS); }

    fn get_handle(&self) -> PosT { self.pos }

    fn set_handle(&mut self, pos: PosT) { self.pos = pos; }
}

impl<PosT: PrimitiveNum> Default for RecentLFUHandle<PosT> {
    fn default() -> Self {
        Self {
            pos: PosT::from(Self::NULL_POS),
        }
    }
}

impl<PosT: PrimitiveNum> CacheIndexTrait for RecentLFUHandle<PosT> {}

type FrequencyType = u16;
// Use 4 bits to randomize order of cache elements with same frequency. This is
// intended to avoid always replacing the most recently accessed element with
// frequency 1 from LRU.
const RANDOM_BITS: FrequencyType = (1u16 << 4) - 1;
const COUNTER_MASK: FrequencyType = !RANDOM_BITS;
/// MAX_VISIT_COUNT == COUNTER_MASK
const MAX_VISIT_COUNT: FrequencyType = ::std::u16::MAX & COUNTER_MASK;

#[derive(MallocSizeOfDerive)]
struct RecentLFUMetadata<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> {
    frequency: FrequencyType,
    lru_handle: LRUHandle<PosT>,
    cache_index: CacheIndexT,
}

impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait>
    RecentLFUMetadata<PosT, CacheIndexT>
{
    fn is_visit_counter_maximum(&self) -> bool {
        self.frequency & COUNTER_MASK == MAX_VISIT_COUNT
    }

    fn init_visit_counter_random_bits<RngT: Rng>(
        rng: &mut RngT,
    ) -> FrequencyType {
        RANDOM_BITS & rng.gen::<FrequencyType>()
    }

    fn inc_visit_counter<RngT: Rng>(&mut self, _rng: &mut RngT) {
        if !self.is_visit_counter_maximum() {
            self.frequency += RANDOM_BITS + 1
        }
    }
}

struct MetadataHeapUtil<
    'a: 'b,
    'b,
    PosT: 'a + PrimitiveNum,
    CacheIndexT: CacheIndexTrait,
    CacheStoreUtilT: 'b
        + CacheStoreUtil<
            CacheAlgoData = RecentLFUHandle<PosT>,
            ElementIndex = CacheIndexT,
        >,
> {
    frequency_lru: &'a mut LRU<PosT, RecentLFUHandle<PosT>>,
    cache_store_util: &'b mut CacheStoreUtilT,
}

impl<
        'a,
        'b,
        PosT: PrimitiveNum,
        CacheIndexT: CacheIndexTrait,
        CacheStoreUtilT: CacheStoreUtil<
            CacheAlgoData = RecentLFUHandle<PosT>,
            ElementIndex = CacheIndexT,
        >,
    > HeapValueUtil<RecentLFUMetadata<PosT, CacheIndexT>, PosT>
    for MetadataHeapUtil<'a, 'b, PosT, CacheIndexT, CacheStoreUtilT>
{
    type KeyType = FrequencyType;

    fn set_handle(
        &mut self, value: &mut RecentLFUMetadata<PosT, CacheIndexT>, pos: PosT,
    ) {
        unsafe {
            self.frequency_lru
                .get_cache_index_mut(value.lru_handle)
                .set_handle(pos);
            CacheAlgoDataAdapter::new_mut(
                self.cache_store_util,
                value.cache_index,
            )
            .placement_new_handle(pos);
        }
    }

    fn set_handle_final(
        &mut self, value: &mut RecentLFUMetadata<PosT, CacheIndexT>, pos: PosT,
    ) {
        unsafe {
            self.frequency_lru
                .get_cache_index_mut(value.lru_handle)
                .set_handle(pos);
            CacheAlgoDataAdapter::new_mut_most_recently_accessed(
                self.cache_store_util,
                value.cache_index,
            )
            .placement_new_handle(pos);
        }
    }

    fn set_removed(
        &mut self, value: &mut RecentLFUMetadata<PosT, CacheIndexT>,
    ) {
        unsafe {
            // There is no need to update lru cache_index because heap removal
            // always happens after frequency_lru removal.
            CacheAlgoDataAdapter::new_mut(
                self.cache_store_util,
                value.cache_index,
            )
            .placement_new_evicted();
        }
    }

    fn get_key_for_comparison<'x>(
        &'x self, value: &'x RecentLFUMetadata<PosT, CacheIndexT>,
    ) -> &Self::KeyType {
        &value.frequency
    }
}

type CacheStoreUtilLRUHit<'a, PosT, CacheIndexT> =
    &'a mut Vec<RecentLFUMetadata<PosT, CacheIndexT>>;

impl<'a, PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> CacheStoreUtil
    for CacheStoreUtilLRUHit<'a, PosT, CacheIndexT>
{
    type CacheAlgoData = LRUHandle<PosT>;
    type ElementIndex = RecentLFUHandle<PosT>;

    fn get(&self, element_index: Self::ElementIndex) -> LRUHandle<PosT> {
        self[MyInto::<usize>::into(element_index.get_handle())].lru_handle
    }

    fn set(
        &mut self, element_index: Self::ElementIndex,
        algo_data: &LRUHandle<PosT>,
    )
    {
        self[MyInto::<usize>::into(element_index.get_handle())].lru_handle =
            *algo_data
    }
}

// TODO: in rust 2018, it's not necessary to write Type: 'a.
struct CacheStoreUtilLRUMiss<
    'a,
    'b,
    PosT: PrimitiveNum + 'a + 'b,
    CacheIndexT: CacheIndexTrait + 'a + 'b,
> {
    metadata: CacheStoreUtilLRUHit<'a, PosT, CacheIndexT>,
    new_metadata: &'b mut RecentLFUMetadata<PosT, CacheIndexT>,
}

impl<'a, 'b, PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait>
    CacheStoreUtilLRUMiss<'a, 'b, PosT, CacheIndexT>
{
    fn new<RngT: Rng>(
        metadata: CacheStoreUtilLRUHit<'a, PosT, CacheIndexT>,
        cache_index: CacheIndexT,
        new_metadata: &'b mut RecentLFUMetadata<PosT, CacheIndexT>,
        rng: &mut RngT,
    ) -> Self
    {
        *new_metadata = RecentLFUMetadata::<PosT, CacheIndexT> {
            frequency:
                RecentLFUMetadata::<PosT, CacheIndexT>::init_visit_counter_random_bits(
                    rng,
                ),
            lru_handle: Default::default(),
            cache_index: cache_index,
        };

        Self {
            new_metadata,
            metadata,
        }
    }
}

impl<'a, 'b, PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> CacheStoreUtil
    for CacheStoreUtilLRUMiss<'a, 'b, PosT, CacheIndexT>
{
    type CacheAlgoData = LRUHandle<PosT>;
    type ElementIndex = RecentLFUHandle<PosT>;

    fn get(&self, element_index: Self::ElementIndex) -> LRUHandle<PosT> {
        self.metadata.get(element_index)
    }

    fn get_most_recently_accessed(
        &self, _element_index: Self::ElementIndex,
    ) -> LRUHandle<PosT> {
        self.new_metadata.lru_handle
    }

    fn set(
        &mut self, element_index: Self::ElementIndex,
        algo_data: &LRUHandle<PosT>,
    )
    {
        self.metadata.set(element_index, algo_data);
    }

    fn set_most_recently_accessed(
        &mut self, _element_index: Self::ElementIndex,
        algo_data: &LRUHandle<PosT>,
    )
    {
        self.new_metadata.lru_handle = *algo_data;
    }
}

impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> CacheAlgorithm
    for RecentLFU<PosT, CacheIndexT>
{
    type CacheAlgoData = RecentLFUHandle<PosT>;
    type CacheIndex = CacheIndexT;

    fn access<
        CacheStoreUtilT: CacheStoreUtil<
            ElementIndex = CacheIndexT,
            CacheAlgoData = RecentLFUHandle<PosT>,
        >,
    >(
        &mut self, cache_index: CacheIndexT,
        cache_store_util: &mut CacheStoreUtilT,
    ) -> CacheAccessResult<CacheIndexT>
    {
        let r_lfu_handle =
            cache_store_util.get_most_recently_accessed(cache_index);
        let is_lru_hit = r_lfu_handle.is_lru_hit();

        if is_lru_hit {
            self.frequency_lru
                .access(r_lfu_handle, &mut self.frequency_heap.get_array_mut());

            // Increase LFU visit counter.
            unsafe {
                self.frequency_heap
                    .get_unchecked_mut(r_lfu_handle.get_handle())
                    .inc_visit_counter(&mut self.counter_rng)
            };

            let has_space = self.has_space();
            let (heap, mut heap_util) =
                self.heap_and_heap_util(cache_store_util);

            if r_lfu_handle.is_lfu_hit(&heap) {
                heap.sift_down(r_lfu_handle.get_handle(), &mut heap_util);
                CacheAccessResult::Hit
            } else {
                // Hit in LRU but not in LFU. The heap may not be full because
                // of deletion.
                unsafe {
                    let r_lfu_metadata_ptr = heap
                        .get_unchecked_mut(r_lfu_handle.get_handle())
                        as *mut RecentLFUMetadata<PosT, CacheIndexT>;

                    let mut hole = Hole::new(r_lfu_metadata_ptr);

                    if has_space {
                        let heap_size = heap.get_heap_size();
                        if heap_size != r_lfu_handle.get_handle() {
                            hole.move_to(
                                heap.get_unchecked_mut(heap_size),
                                r_lfu_handle.get_handle(),
                                &mut heap_util,
                            );
                        }
                        heap.set_heap_size_unchecked(heap_size + PosT::from(1));

                        heap.sift_up_with_hole(heap_size, hole, &mut heap_util);

                        CacheAccessResult::MissInsert
                    } else {
                        hole.move_to(
                            heap.get_unchecked_mut(PosT::from(0)),
                            r_lfu_handle.get_handle(),
                            &mut heap_util,
                        );
                        heap.sift_down_with_hole(
                            PosT::from(0),
                            hole,
                            &mut heap_util,
                        );
                        CacheAccessResult::MissReplaced {
                            evicted: vec![],
                            evicted_keep_cache_algo_data: vec![
                                (*r_lfu_metadata_ptr).cache_index,
                            ],
                        }
                    }
                }
            }
        } else {
            // r_lfu_handle equals NULL_POS.
            if self.frequency_lru.has_space() {
                let mut hole: Hole<RecentLFUMetadata<PosT, CacheIndexT>> =
                    unsafe { mem::uninitialized() };
                {
                    let mut lru_cache_store_util = CacheStoreUtilLRUMiss::new(
                        self.frequency_heap.get_array_mut(),
                        cache_index,
                        &mut hole.value,
                        &mut self.counter_rng,
                    );

                    self.frequency_lru
                        .access(r_lfu_handle, &mut lru_cache_store_util);
                }

                let has_space = self.has_space();
                let (heap, mut heap_util) =
                    self.heap_and_heap_util(cache_store_util);
                if has_space {
                    unsafe {
                        heap.insert_with_hole_unchecked(hole, &mut heap_util)
                    };

                    CacheAccessResult::MissInsert
                } else {
                    let pos = unsafe {
                        heap.hole_push_back_and_swap_unchecked(
                            PosT::from(0),
                            &mut hole,
                            &mut heap_util,
                        )
                    };
                    heap.sift_down_with_hole(
                        PosT::from(0),
                        hole,
                        &mut heap_util,
                    );

                    CacheAccessResult::MissReplaced {
                        evicted: vec![],
                        evicted_keep_cache_algo_data: vec![unsafe {
                            heap.get_unchecked_mut(pos).cache_index
                        }],
                    }
                }
            } else {
                let mut hole: Hole<RecentLFUMetadata<PosT, CacheIndexT>> =
                    unsafe { mem::uninitialized() };
                let lru_access_result;
                {
                    let mut lru_cache_store_util = CacheStoreUtilLRUMiss::new(
                        self.frequency_heap.get_array_mut(),
                        cache_index,
                        &mut hole.value,
                        &mut self.counter_rng,
                    );
                    lru_access_result = self
                        .frequency_lru
                        .access(r_lfu_handle, &mut lru_cache_store_util);
                }

                let (heap, mut heap_util) =
                    self.heap_and_heap_util(cache_store_util);

                match lru_access_result {
                    CacheAccessResult::MissReplaced {
                        evicted: lru_evicted_keys,
                        evicted_keep_cache_algo_data: _, // known to be empty.
                    } => {
                        // It's known to contain exactly one item.
                        let lru_evicted =
                            unsafe { lru_evicted_keys.get_unchecked(0) };

                        let evicted_cache_index;
                        let evicted_r_lfu_metadata_ptr;
                        {
                            let evicted_r_lfu_metadata = unsafe {
                                heap.get_unchecked_mut(lru_evicted.pos)
                            };
                            evicted_cache_index =
                                evicted_r_lfu_metadata.cache_index;
                            hole.pointer_pos = evicted_r_lfu_metadata;

                            // The caller should read the the returned
                            // CacheAccessResult and
                            // removes the evicted keys.
                            // set_removed isn't necessary but prevent
                            // mysterious
                            // errors if the caller doesn't.
                            heap_util.set_removed(evicted_r_lfu_metadata);

                            evicted_r_lfu_metadata_ptr = evicted_r_lfu_metadata
                                as *mut RecentLFUMetadata<PosT, CacheIndexT>
                        }
                        if lru_evicted.is_lfu_hit(heap) {
                            // The element removed from LRU also lives in LFU.
                            // Replace it with the newly accessed item.

                            unsafe {
                                heap.replace_at_unchecked_with_hole(
                                    lru_evicted.pos,
                                    hole,
                                    &mut *evicted_r_lfu_metadata_ptr,
                                    &mut heap_util,
                                )
                            };
                            CacheAccessResult::MissReplaced {
                                evicted: vec![evicted_cache_index],
                                evicted_keep_cache_algo_data: vec![],
                            }
                        } else {
                            // The element removed from LRU lives outside LFU.
                            // Replace the least frequently visited with the
                            // newly accessed item and keep the least frequently
                            // visited in LRU.
                            let lfu_evicted = unsafe {
                                heap.get_unchecked_mut(PosT::from(0))
                                    .cache_index
                            };
                            hole.move_to(
                                unsafe {
                                    heap.get_unchecked_mut(PosT::from(0))
                                },
                                lru_evicted.pos,
                                &mut heap_util,
                            );

                            heap.sift_down_with_hole(
                                PosT::from(0),
                                hole,
                                &mut heap_util,
                            );

                            CacheAccessResult::MissReplaced {
                                evicted: vec![evicted_cache_index],
                                evicted_keep_cache_algo_data: vec![lfu_evicted],
                            }
                        }
                    }
                    _ => unsafe { hint::unreachable_unchecked() },
                }
            }
        }
    }

    fn delete<
        CacheStoreUtilT: CacheStoreUtil<
            ElementIndex = CacheIndexT,
            CacheAlgoData = RecentLFUHandle<PosT>,
        >,
    >(
        &mut self, cache_index: CacheIndexT,
        cache_store_util: &mut CacheStoreUtilT,
    )
    {
        let r_lfu_handle = cache_store_util.get(cache_index);
        self.frequency_lru
            .delete(r_lfu_handle, &mut self.frequency_heap.get_array_mut());
        // Remove from heap.
        let (heap, mut heap_util) = self.heap_and_heap_util(cache_store_util);
        unsafe {
            heap.remove_at_unchecked(r_lfu_handle.get_handle(), &mut heap_util);
        }
    }

    fn log_usage(&self, prefix: &str) {
        self.frequency_lru.log_usage("{} recent_lfu#frequency ");
        debug!(
            "{}recent_lfu: capacity {}, size {}",
            prefix,
            self.capacity,
            self.frequency_heap.get_heap_size()
        );
    }
}

// The code is used in tests.
#[allow(dead_code)]
impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait>
    RecentLFU<PosT, CacheIndexT>
{
    pub fn new(capacity: PosT, lru_capacity: PosT) -> Self {
        Self {
            capacity,
            frequency_heap: RemovableHeap::new(lru_capacity),
            frequency_lru: LRU::new(lru_capacity),
            counter_rng: ChaChaRng::from_entropy(),
        }
    }

    fn heap_and_heap_util<
        'a,
        'b,
        CacheStoreUtilT: CacheStoreUtil<
            ElementIndex = CacheIndexT,
            CacheAlgoData = RecentLFUHandle<PosT>,
        >,
    >(
        &'a mut self, cache_store_util: &'b mut CacheStoreUtilT,
    ) -> (
        &mut RemovableHeap<PosT, RecentLFUMetadata<PosT, CacheIndexT>>,
        MetadataHeapUtil<'a, 'b, PosT, CacheIndexT, CacheStoreUtilT>,
    ) {
        (
            &mut self.frequency_heap,
            MetadataHeapUtil::<PosT, CacheIndexT, CacheStoreUtilT> {
                frequency_lru: &mut self.frequency_lru,
                cache_store_util,
            },
        )
    }

    pub fn has_space(&self) -> bool {
        self.capacity != self.frequency_heap.get_heap_size()
    }

    pub fn is_full(&self) -> bool {
        self.capacity == self.frequency_heap.get_heap_size()
    }
}
