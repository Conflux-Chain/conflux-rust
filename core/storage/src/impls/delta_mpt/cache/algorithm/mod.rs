// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod lru;
pub mod recent_lfu;
pub mod removable_heap;

#[cfg(test)]
mod tests;

/// The cache algorithm should store a reference to the cached element in order
/// to link between cache store and internal data structure of cache algorithm.
/// Normally this should be simple type like pointer, or map key for the
/// element.
///
/// User may use a 32bit data type to reduce memory usage.
pub trait CacheIndexTrait: Copy + Send + MallocSizeOf {}

pub trait CacheAlgoDataTrait: Copy + Default + Send + MallocSizeOf {}

/// The cache storage interface that user should implement for cache algorithm
/// to update reference from cached object to its internal data structure.
///
/// The cache algorithm should normally call the interface sequentially.
pub trait CacheStoreUtil {
    type CacheAlgoData: CacheAlgoDataTrait;
    type ElementIndex: CacheIndexTrait;

    fn get(&self, element_index: Self::ElementIndex) -> Self::CacheAlgoData;

    fn get_most_recently_accessed(
        &self, element_index: Self::ElementIndex,
    ) -> Self::CacheAlgoData {
        self.get(element_index)
    }

    fn set(
        &mut self, element_index: Self::ElementIndex,
        algo_data: &Self::CacheAlgoData,
    );

    /// In some cases only temporary space in cache store is available for most
    /// recently accessed (new) element. This method offers possibility for this
    /// special case. Cache algorithm should always call this method to set
    /// for the most recently accessed element.
    ///
    /// Without an overriding implementation, calls to this method is forwarded
    /// to the normal set method.
    fn set_most_recently_accessed(
        &mut self, element_index: Self::ElementIndex,
        algo_data: &Self::CacheAlgoData,
    )
    {
        self.set(element_index, algo_data);
    }
}

struct CacheAlgoDataAdapter<
    CacheStoreUtilT: CacheStoreUtil,
    CacheIndexT: CacheIndexTrait,
> where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    _marker_s: PhantomData<CacheStoreUtilT>,
    _marker_i: PhantomData<CacheIndexT>,
}

impl<
        CacheStoreUtilT: CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > CacheAlgoDataAdapter<CacheStoreUtilT, CacheIndexT>
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    fn get(
        util: &CacheStoreUtilT, index: CacheIndexT,
    ) -> CacheStoreUtilT::CacheAlgoData {
        util.get(index)
    }

    /// It's impossible to abstract get_mut directly in CacheStoreUtil,
    /// therefore we have CacheAlgoDataAdapter.
    fn get_mut(
        util: &mut CacheStoreUtilT, index: CacheIndexT,
    ) -> CacheAlgoDataSetter<CacheStoreUtilT, CacheIndexT> {
        let data = Self::get(util, index).clone();
        CacheAlgoDataSetter {
            cache_store_util: util,
            element_index: index,
            algo_data: data,
        }
    }

    #[allow(unused)]
    fn get_mut_most_recently_accessed(
        util: &mut CacheStoreUtilT, index: CacheIndexT,
    ) -> CacheAlgoDataSetterMostRecentlyAccessed<CacheStoreUtilT, CacheIndexT>
    {
        let data = util.get_most_recently_accessed(index).clone();
        CacheAlgoDataSetterMostRecentlyAccessed {
            cache_store_util: util,
            element_index: index,
            algo_data: data,
        }
    }

    unsafe fn new_mut(
        util: &mut CacheStoreUtilT, index: CacheIndexT,
    ) -> CacheAlgoDataSetter<CacheStoreUtilT, CacheIndexT> {
        CacheAlgoDataSetter {
            cache_store_util: util,
            element_index: index,
            algo_data: mem::uninitialized(),
        }
    }

    unsafe fn new_mut_most_recently_accessed(
        util: &mut CacheStoreUtilT, index: CacheIndexT,
    ) -> CacheAlgoDataSetterMostRecentlyAccessed<CacheStoreUtilT, CacheIndexT>
    {
        CacheAlgoDataSetterMostRecentlyAccessed {
            cache_store_util: util,
            element_index: index,
            algo_data: mem::uninitialized(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CacheAccessResult<CacheIndexT> {
    Hit,
    MissInsert,
    MissReplaced {
        evicted: Vec<CacheIndexT>,
        evicted_keep_cache_algo_data: Vec<CacheIndexT>,
    },
}

pub trait CacheAlgorithm: Send {
    type CacheIndex: CacheIndexTrait;
    type CacheAlgoData: CacheAlgoDataTrait;

    /// The cache index is the identifier for content being cached. If user want
    /// to reuse the cache storage of evicted cache element, it should be
    /// done in the cache storage.
    fn access<
        CacheStoreUtilT: CacheStoreUtil<
            ElementIndex = Self::CacheIndex,
            CacheAlgoData = Self::CacheAlgoData,
        >,
    >(
        &mut self, cache_index: Self::CacheIndex,
        cache_store_util: &mut CacheStoreUtilT,
    ) -> CacheAccessResult<Self::CacheIndex>;

    /// When an element is removed because of external logic, update the cache
    /// algorithm.
    ///
    /// Note 1: do not use cache_store_util which implements special
    /// logic for most recently accessed cache index, because the case
    /// doesn't apply in deletion.
    ///
    /// Note 2: Since the cache deletion updates cache_algo_data for the element
    /// to delete, caller must delete the item after the call to this delete
    /// method has finished.
    fn delete<
        CacheStoreUtilT: CacheStoreUtil<
            ElementIndex = Self::CacheIndex,
            CacheAlgoData = Self::CacheAlgoData,
        >,
    >(
        &mut self, cache_index: Self::CacheIndex,
        cache_store_util: &mut CacheStoreUtilT,
    );

    fn log_usage(&self, prefix: &str);
}

// TODO(yz): maybe replace it with a library.
pub trait PrimitiveNum:
    Copy
    + Debug
    + Display
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Div<Output = Self>
    + DivAssign
    + Mul<Output = Self>
    + PartialOrd
    + PartialEq
    + MyInto<usize>
    + MyInto<isize>
    + MyFrom<i32>
    + MyFrom<usize>
    + Send
    + MallocSizeOf
{
}

pub trait MyFrom<X> {
    fn from(x: X) -> Self;
}

pub trait MyInto<X> {
    fn into(self) -> X;
}

impl MyFrom<usize> for u32 {
    fn from(x: usize) -> Self { x as Self }
}

impl MyFrom<i32> for u32 {
    fn from(x: i32) -> Self { x as Self }
}

impl MyInto<isize> for u32 {
    fn into(self) -> isize { self as isize }
}

impl MyInto<usize> for u32 {
    fn into(self) -> usize { self as usize }
}

impl PrimitiveNum for u32 {}

struct CacheAlgoDataSetter<
    'a,
    CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
    CacheIndexT: CacheIndexTrait,
> where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    algo_data: CacheStoreUtilT::CacheAlgoData,
    element_index: CacheIndexT,
    cache_store_util: &'a mut CacheStoreUtilT,
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > Drop for CacheAlgoDataSetter<'a, CacheStoreUtilT, CacheIndexT>
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    fn drop(&mut self) {
        let (util, index, data) = (
            &mut self.cache_store_util,
            &self.element_index,
            &self.algo_data,
        );
        util.set(*index, data);
    }
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > Deref for CacheAlgoDataSetter<'a, CacheStoreUtilT, CacheIndexT>
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    type Target = CacheStoreUtilT::CacheAlgoData;

    fn deref(&self) -> &Self::Target { &self.algo_data }
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > DerefMut for CacheAlgoDataSetter<'a, CacheStoreUtilT, CacheIndexT>
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.algo_data }
}

struct CacheAlgoDataSetterMostRecentlyAccessed<
    'a,
    CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
    CacheIndexT: CacheIndexTrait,
> where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    algo_data: CacheStoreUtilT::CacheAlgoData,
    element_index: CacheIndexT,
    cache_store_util: &'a mut CacheStoreUtilT,
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > Drop
    for CacheAlgoDataSetterMostRecentlyAccessed<
        'a,
        CacheStoreUtilT,
        CacheIndexT,
    >
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    fn drop(&mut self) {
        let (util, index, data) = (
            &mut self.cache_store_util,
            &self.element_index,
            &self.algo_data,
        );
        util.set_most_recently_accessed(*index, data);
    }
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > Deref
    for CacheAlgoDataSetterMostRecentlyAccessed<
        'a,
        CacheStoreUtilT,
        CacheIndexT,
    >
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    type Target = CacheStoreUtilT::CacheAlgoData;

    fn deref(&self) -> &Self::Target { &self.algo_data }
}

impl<
        'a,
        CacheStoreUtilT: 'a + CacheStoreUtil<ElementIndex = CacheIndexT>,
        CacheIndexT: CacheIndexTrait,
    > DerefMut
    for CacheAlgoDataSetterMostRecentlyAccessed<
        'a,
        CacheStoreUtilT,
        CacheIndexT,
    >
where CacheStoreUtilT::CacheAlgoData: CacheAlgoDataTrait
{
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.algo_data }
}

use malloc_size_of::MallocSizeOf;
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
    mem,
    ops::{
        Add, AddAssign, Deref, DerefMut, Div, DivAssign, Mul, Sub, SubAssign,
    },
};
