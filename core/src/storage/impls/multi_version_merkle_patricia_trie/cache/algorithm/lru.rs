// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    CacheAccessResult, CacheAlgoDataAdapter, CacheAlgoDataTrait,
    CacheAlgorithm, CacheIndexTrait, CacheStoreUtil, MyInto, PrimitiveNum,
};
use std::{mem::replace, vec::Vec};

#[derive(Clone, Copy)]
pub struct LRUHandle<PosT: PrimitiveNum> {
    prev_pos: PosT,
}

impl<PosT: PrimitiveNum> CacheAlgoDataTrait for LRUHandle<PosT> {}

impl<PosT: PrimitiveNum> LRUHandle<PosT> {
    pub const HEAD_POS: i32 = -2;
    pub const NULL_POS: i32 = -1;

    // LRU capacity must < max PosT - 1 (i.e. != NULL_POS) in order to reserve
    // HEAD_POS and NULL_POS.

    fn placement_new_most_recently_accessed(&mut self) {
        self.set_most_recently_accessed();
    }

    fn placement_new_handle(&mut self, prev_pos: PosT) {
        self.set_handle(prev_pos);
    }

    fn placement_new_evicted(&mut self) { self.set_evicted(); }

    pub fn is_hit(&self) -> bool { self.prev_pos != PosT::from(Self::NULL_POS) }

    fn set_evicted(&mut self) { self.prev_pos = PosT::from(Self::NULL_POS); }

    pub fn is_most_recently_accessed(&self) -> bool {
        self.prev_pos == PosT::from(Self::HEAD_POS)
    }

    pub fn set_most_recently_accessed(&mut self) {
        self.prev_pos = PosT::from(Self::HEAD_POS);
    }

    fn get_prev_pos(&self) -> PosT { self.prev_pos }

    fn set_handle(&mut self, prev_pos: PosT) { self.prev_pos = prev_pos; }
}

impl<PosT: PrimitiveNum> Default for LRUHandle<PosT> {
    fn default() -> Self {
        Self {
            prev_pos: PosT::from(Self::NULL_POS),
        }
    }
}

struct DoubleLinkListNode<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> {
    next: PosT,
    /// prev link is stored in LRUHandle<PosT>
    cache_index: CacheIndexT,
}

pub struct LRU<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> {
    size: PosT,
    capacity: PosT,
    head: PosT,
    rear: PosT,
    recent: Vec<DoubleLinkListNode<PosT, CacheIndexT>>,
}

impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> LRU<PosT, CacheIndexT> {
    pub fn new(capacity: PosT) -> Self {
        if capacity == PosT::from(LRUHandle::<PosT>::NULL_POS) {
            panic!("LRU: capacity {:?} is too large!", capacity)
        }

        Self {
            size: PosT::from(0),
            capacity,
            head: PosT::from(LRUHandle::<PosT>::NULL_POS),
            rear: PosT::from(LRUHandle::<PosT>::HEAD_POS),
            recent: Vec::with_capacity(capacity.into()),
        }
    }
}

impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> CacheAlgorithm
    for LRU<PosT, CacheIndexT>
{
    type CacheAlgoData = LRUHandle<PosT>;
    type CacheIndex = CacheIndexT;

    fn access<
        CacheStoreUtilT: CacheStoreUtil<
            CacheAlgoData = LRUHandle<PosT>,
            ElementIndex = CacheIndexT,
        >,
    >(
        &mut self, cache_index: CacheIndexT,
        cache_store_util: &mut CacheStoreUtilT,
    ) -> CacheAccessResult<CacheIndexT>
    {
        // Not using get_mut because it borrows cache_store_util which conflicts
        // with later CacheAlgoDataAdapter calls.
        let lru_handle =
            cache_store_util.get_most_recently_accessed(cache_index);
        let is_hit = lru_handle.is_hit();

        if is_hit {
            if lru_handle.is_most_recently_accessed() {
                // Nothing to do, access the most recently visited element.
            } else {
                let prev_pos = lru_handle.get_prev_pos();
                let element_pos =
                    unsafe { self.get_unchecked_mut(prev_pos).next };
                // Move the accessed element to head.
                let old_head = self.head;

                // Update rear.
                if element_pos == self.rear {
                    self.rear = prev_pos;
                }
                // Update prev_pos. There is no need to update if it's the rear.
                else {
                    unsafe {
                        let next = self.get_unchecked_mut(element_pos).next;
                        self.get_unchecked_mut(prev_pos).next = next;
                        CacheAlgoDataAdapter::new_mut(
                            cache_store_util,
                            self.get_unchecked_mut(next).cache_index,
                        )
                        .placement_new_handle(prev_pos);
                    }
                }

                // Set new head.
                self.head = element_pos;
                unsafe {
                    self.get_unchecked_mut(element_pos).next = old_head;
                    CacheAlgoDataAdapter::new_mut_most_recently_accessed(
                        cache_store_util,
                        cache_index,
                    )
                    .placement_new_most_recently_accessed();
                }

                // Update old head.
                unsafe {
                    CacheAlgoDataAdapter::new_mut(
                        cache_store_util,
                        self.get_unchecked_mut(old_head).cache_index,
                    )
                    .placement_new_handle(element_pos);
                }
            }

            CacheAccessResult::Hit
        } else if self.size < self.capacity {
            let old_head = self.head;

            // Set new head.
            let new_head = self.size;
            self.head = new_head;
            unsafe {
                CacheAlgoDataAdapter::new_mut_most_recently_accessed(
                    cache_store_util,
                    cache_index,
                )
                .set_most_recently_accessed();
            }
            self.recent.push(DoubleLinkListNode {
                next: old_head,
                cache_index,
            });

            // Update rear.
            if self.size == PosT::from(0) {
                self.rear = PosT::from(0);
            } else {
                // Update old head.
                unsafe {
                    CacheAlgoDataAdapter::new_mut(
                        cache_store_util,
                        self.get_unchecked_mut(old_head).cache_index,
                    )
                    .placement_new_handle(new_head);
                }
            }

            self.size += PosT::from(1);

            CacheAccessResult::MissInsert
        } else {
            let new_head = self.rear;
            let old_head = self.head;

            // Update old head.
            CacheAlgoDataAdapter::get_mut(cache_store_util, unsafe {
                self.get_unchecked_mut(old_head).cache_index
            })
            .set_handle(new_head);

            let evicted_cache_index;
            {
                let mut rear_handle;
                {
                    let rear_cache_index_mut = unsafe {
                        &mut self.get_unchecked_mut(new_head).cache_index
                    };
                    rear_handle = CacheAlgoDataAdapter::get_mut(
                        cache_store_util,
                        *rear_cache_index_mut,
                    );

                    // Set cache_index for new head.
                    evicted_cache_index =
                        replace(rear_cache_index_mut, cache_index);
                }

                // Update rear.
                self.rear = rear_handle.get_prev_pos();
                // No need to set the next field of rear.

                // Evict least recent used and
                rear_handle.set_evicted();
            }

            // Insert new head.
            self.head = new_head;
            unsafe {
                self.get_unchecked_mut(new_head).next = old_head;
                CacheAlgoDataAdapter::new_mut_most_recently_accessed(
                    cache_store_util,
                    cache_index,
                )
                .placement_new_most_recently_accessed();
            }

            CacheAccessResult::MissReplaced {
                evicted: vec![evicted_cache_index],
                evicted_keep_cache_algo_data: vec![],
            }
        }
    }

    fn delete<
        CacheStoreUtilT: CacheStoreUtil<
            CacheAlgoData = LRUHandle<PosT>,
            ElementIndex = CacheIndexT,
        >,
    >(
        &mut self, cache_index: CacheIndexT,
        cache_store_util: &mut CacheStoreUtilT,
    )
    {
        let lru_handle = cache_store_util.get(cache_index);

        if lru_handle.is_hit() {
            // First delete this entry.
            let pos_to_delete = self.get_lru_pos_for_handle(&lru_handle);
            CacheAlgoDataAdapter::get_mut(cache_store_util, cache_index)
                .set_evicted();
            if pos_to_delete == self.rear {
                self.rear = lru_handle.get_prev_pos();
                if pos_to_delete == self.head {
                    self.head = PosT::from(LRUHandle::<PosT>::NULL_POS);
                }
            } else {
                let next_pos;
                unsafe {
                    next_pos = self.get_unchecked_mut(pos_to_delete).next;
                    if pos_to_delete != self.head {
                        let prev_pos = lru_handle.get_prev_pos();
                        self.get_unchecked_mut(prev_pos).next = next_pos;
                    } else {
                        self.head = next_pos;
                    }

                    CacheAlgoDataAdapter::get_mut(
                        cache_store_util,
                        self.get_unchecked_mut(next_pos).cache_index,
                    )
                    .set_handle(lru_handle.get_prev_pos());
                }
            }
            // Move the element at size to pos.
            self.size -= PosT::from(1);
            let pos_to_move = self.size;
            if pos_to_delete != pos_to_move {
                let lru_handle = CacheAlgoDataAdapter::get(
                    cache_store_util,
                    unsafe { self.get_unchecked_mut(pos_to_move) }.cache_index,
                );
                if lru_handle.is_most_recently_accessed() {
                    self.head = pos_to_delete;
                } else {
                    unsafe {
                        self.get_unchecked_mut(lru_handle.get_prev_pos())
                            .next = pos_to_delete;
                    }
                }

                if pos_to_move != self.rear {
                    unsafe {
                        let next = self.get_unchecked_mut(pos_to_move).next;
                        CacheAlgoDataAdapter::new_mut(
                            cache_store_util,
                            self.get_unchecked_mut(next).cache_index,
                        )
                        .placement_new_handle(pos_to_delete);
                    }
                } else {
                    self.rear = pos_to_delete;
                }

                self.recent.swap_remove(pos_to_delete.into());
            } else {
                self.recent.remove(pos_to_delete.into());
            }
        }
    }

    fn log_usage(&self, prefix: &String) {
        debug!(
            "{}lru: capacity {}, size {}",
            prefix, self.capacity, self.size
        );
    }
}

impl<PosT: PrimitiveNum, CacheIndexT: CacheIndexTrait> LRU<PosT, CacheIndexT> {
    fn get_lru_pos_for_handle(&mut self, handle: &LRUHandle<PosT>) -> PosT {
        let element_pos;
        if handle.is_most_recently_accessed() {
            element_pos = self.head;
        } else {
            element_pos =
                unsafe { self.get_unchecked_mut(handle.get_prev_pos()).next };
        }

        element_pos
    }

    unsafe fn get_unchecked_mut(
        &mut self, pos: PosT,
    ) -> &mut DoubleLinkListNode<PosT, CacheIndexT> {
        self.recent.get_unchecked_mut(MyInto::<usize>::into(pos))
    }

    /// User may update the cache index.
    /// unsafe because we didn't check for invalid handles.
    pub unsafe fn get_cache_index_mut(
        &mut self, handle: LRUHandle<PosT>,
    ) -> &mut CacheIndexT {
        let pos = self.get_lru_pos_for_handle(&handle);
        return &mut self.get_unchecked_mut(pos).cache_index;
    }

    pub fn has_space(&self) -> bool { self.capacity != self.size }

    pub fn is_full(&self) -> bool { self.capacity == self.size }

    pub fn is_empty(&self) -> bool { PosT::from(0) == self.size }
}
