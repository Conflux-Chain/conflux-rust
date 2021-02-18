impl CacheIndexTrait for DeltaMptId {}

struct CacheUtil {
    cache_data: HashMap<
        DeltaMptId,
        (Arc<dyn DeltaDbTrait + Send + Sync>, LRUHandle<u32>),
    >,
}

impl CacheStoreUtil for CacheUtil {
    type CacheAlgoData = LRUHandle<u32>;
    type ElementIndex = DeltaMptId;

    fn get(&self, element_index: DeltaMptId) -> LRUHandle<u32> {
        match self.cache_data.get(&element_index) {
            Some(tuple) => tuple.1,
            None => {
                unreachable!();
            }
        }
    }

    fn set(&mut self, element_index: DeltaMptId, algo_data: &LRUHandle<u32>) {
        match self.cache_data.get_mut(&element_index) {
            Some(tuple) => tuple.1 = *algo_data,
            None => {
                unreachable!();
            }
        }
    }
}

pub struct ArcDeltaDbWrapper {
    // inner will always be Some() before drop
    inner: Option<Arc<dyn DeltaDbTrait>>,
    lru: Option<Weak<Mutex<dyn OnDemandOpenDeltaDbInnerTrait>>>,
    mpt_id: DeltaMptId,
}

impl ArcDeltaDbWrapper {
    pub fn db_ref(&self) -> &dyn DeltaDbTrait {
        self.inner.as_ref().unwrap().as_ref()
    }
}

impl Deref for ArcDeltaDbWrapper {
    type Target = dyn DeltaDbTrait;

    fn deref(&self) -> &Self::Target { self.inner.as_ref().unwrap().as_ref() }
}

impl Drop for ArcDeltaDbWrapper {
    fn drop(&mut self) {
        Weak::upgrade(self.lru.as_ref().unwrap()).map(|lru| {
            let mut lru_lock = lru.lock();
            let maybe_arc_db = self.inner.take();
            let need_release =
                Arc::strong_count(maybe_arc_db.as_ref().unwrap()) == 2;
            drop(maybe_arc_db);
            if need_release {
                lru_lock.release(self.mpt_id, false);
            }
        });
    }
}

impl KeyValueDbTypes for ArcDeltaDbWrapper {
    type ValueType = Box<[u8]>;
}

impl KeyValueDbTraitRead for ArcDeltaDbWrapper {
    fn get(&self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        (**self).get(key)
    }
}

mark_kvdb_multi_reader!(ArcDeltaDbWrapper);

trait OnDemandOpenDeltaDbInnerTrait: Send + Sync {
    fn open(&mut self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper>;
    fn create(
        &mut self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
        opened_db: Option<Arc<dyn DeltaDbTrait + Send + Sync>>,
    ) -> Result<ArcDeltaDbWrapper>;
    fn release(&mut self, mpt_id: DeltaMptId, destroy: bool);
}

pub trait OpenableOnDemandOpenDeltaDbTrait: Send + Sync {
    fn open(&self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper>;
}

pub struct OpenDeltaDbLru<DeltaDbManager: DeltaDbManagerTrait> {
    inner: Arc<Mutex<dyn OnDemandOpenDeltaDbInnerTrait>>,
    phantom: PhantomData<DeltaDbManager>,
}

impl<T: 'static + DeltaDbManagerTrait + Send + Sync> OpenDeltaDbLru<T>
where T::DeltaDb: 'static + Send + Sync + DeltaDbTrait
{
    pub fn new(delta_db_manager: Arc<T>) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(OpenDeltaDbLruInner::new(
                delta_db_manager,
            )?)),
            phantom: PhantomData,
        })
    }

    pub fn create(
        &self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
    ) -> Result<ArcDeltaDbWrapper> {
        let mut arc_db = self
            .inner
            .lock()
            .create(snapshot_epoch_id, mpt_id, None)
            .unwrap();
        arc_db.lru = Some(Arc::downgrade(&self.inner));
        Ok(arc_db)
    }

    pub fn import(
        &self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
        opened_db: T::DeltaDb,
    ) -> Result<ArcDeltaDbWrapper>
    {
        let mut arc_db = self
            .inner
            .lock()
            .create(snapshot_epoch_id, mpt_id, Some(Arc::new(opened_db)))
            .unwrap();
        arc_db.lru = Some(Arc::downgrade(&self.inner));
        Ok(arc_db)
    }

    pub fn release(&self, mpt_id: DeltaMptId, destroy: bool) {
        self.inner.lock().release(mpt_id, destroy);
    }
}

impl<T: 'static + DeltaDbManagerTrait + Send + Sync>
    OpenableOnDemandOpenDeltaDbTrait for OpenDeltaDbLru<T>
where T::DeltaDb: 'static + Send + Sync + DeltaDbTrait
{
    fn open(&self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper> {
        let mut arc_db = self.inner.lock().open(mpt_id).unwrap();
        arc_db.lru = Some(Arc::downgrade(&self.inner));
        Ok(arc_db)
    }
}

pub struct OpenDeltaDbLruInner<DeltaDbManager: DeltaDbManagerTrait> {
    delta_db_manager: Arc<DeltaDbManager>,
    mpt_id_to_snapshot_epoch_id: HashMap<DeltaMptId, EpochId>,
    cache_util: CacheUtil,
    lru: LRU<u32, DeltaMptId>,
}

impl<T: DeltaDbManagerTrait + Send + Sync> OpenDeltaDbLruInner<T>
where T::DeltaDb: 'static + Send + Sync + DeltaDbTrait
{
    pub fn new(delta_db_manager: Arc<T>) -> Result<Self> {
        Ok(Self {
            delta_db_manager,
            mpt_id_to_snapshot_epoch_id: HashMap::new(),
            cache_util: CacheUtil {
                cache_data: HashMap::new(),
            },
            lru: LRU::<u32, DeltaMptId>::new(3),
        })
    }

    fn lru_access(&mut self, mpt_id: DeltaMptId) {
        match self.lru.access(mpt_id, &mut self.cache_util) {
            CacheAccessResult::MissReplaced {
                evicted: lru_evicted_keys,
                evicted_keep_cache_algo_data: _,
            } => {
                // It's known to contain exactly one item.
                let lru_evicted = unsafe { lru_evicted_keys.get_unchecked(0) };
                self.release(*lru_evicted, false);
            }
            _ => {}
        }
    }
}

impl<T: DeltaDbManagerTrait + Send + Sync> OnDemandOpenDeltaDbInnerTrait
    for OpenDeltaDbLruInner<T>
where T::DeltaDb: 'static + Send + Sync + DeltaDbTrait
{
    fn open(&mut self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper> {
        match self.cache_util.cache_data.get(&mpt_id) {
            Some(tuple) => {
                let arc_db = tuple.0.clone();
                self.lru_access(mpt_id);
                Ok(ArcDeltaDbWrapper {
                    inner: Some(arc_db),
                    lru: None,
                    mpt_id,
                })
            }
            None => {
                let snapshot_epoch_id =
                    self.mpt_id_to_snapshot_epoch_id.get(&mpt_id).unwrap();
                let arc_db = Arc::new(
                    self.delta_db_manager
                        .get_delta_db(
                            &self
                                .delta_db_manager
                                .get_delta_db_name(snapshot_epoch_id),
                        )?
                        .unwrap(),
                );
                self.cache_util.cache_data.insert(
                    mpt_id,
                    (arc_db.clone(), LRUHandle::<u32>::default()),
                );
                self.lru_access(mpt_id);
                Ok(ArcDeltaDbWrapper {
                    inner: Some(arc_db),
                    lru: None,
                    mpt_id,
                })
            }
        }
    }

    fn create(
        &mut self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
        opened_db: Option<Arc<dyn DeltaDbTrait + Send + Sync>>,
    ) -> Result<ArcDeltaDbWrapper>
    {
        match self.mpt_id_to_snapshot_epoch_id.get(&mpt_id) {
            Some(epoch_id) => {
                debug_assert!(snapshot_epoch_id == epoch_id);
                match opened_db {
                    Some(_arc) => unreachable!(),
                    None => self.open(mpt_id),
                }
            }
            None => {
                let arc_db = match opened_db {
                    Some(arc) => arc,
                    None => Arc::new(
                        self.delta_db_manager.new_empty_delta_db(
                            &self
                                .delta_db_manager
                                .get_delta_db_name(snapshot_epoch_id),
                        )?,
                    ),
                };
                self.mpt_id_to_snapshot_epoch_id
                    .insert(mpt_id, snapshot_epoch_id.clone());
                self.cache_util.cache_data.insert(
                    mpt_id,
                    (arc_db.clone(), LRUHandle::<u32>::default()),
                );
                self.lru_access(mpt_id);
                Ok(ArcDeltaDbWrapper {
                    inner: Some(arc_db),
                    lru: None,
                    mpt_id,
                })
            }
        }
    }

    // Release function is to close opened dbs which are not in lru and
    // are not using. With destroy = true, it will delete db in disk.

    // Lru will hold arc db which is_hit() == true, so if no one holds
    // related ArcDeltaDbWrapper, ref count of arc is always 1. And
    // for evicted arc db, lru will immediately drop it only if ref count
    // == 1, to avoid double open db error. Otherwise, lru will still
    // hold evicted arc db until last drop of related ArcDeltaDbWrapper.
    fn release(&mut self, mpt_id: DeltaMptId, destroy: bool) {
        match self.cache_util.cache_data.get(&mpt_id) {
            Some(tuple) => {
                let strong_count = Arc::strong_count(&tuple.0);
                if destroy {
                    debug_assert!(strong_count == 1);
                }
                if destroy || (strong_count == 1 && !tuple.1.is_hit()) {
                    // If is_hit() == false, lru.delete will do nothing
                    self.lru.delete(mpt_id, &mut self.cache_util);
                    self.cache_util.cache_data.remove(&mpt_id);
                }
            }
            None => {}
        }
        if destroy {
            self.mpt_id_to_snapshot_epoch_id.remove(&mpt_id);
        }
    }
}

use crate::{
    impls::{
        delta_mpt::{
            cache::algorithm::{
                lru::{LRUHandle, LRU},
                CacheAccessResult, CacheAlgorithm, CacheIndexTrait,
                CacheStoreUtil,
            },
            node_ref_map::DeltaMptId,
        },
        errors::*,
    },
    storage_db::{key_value_db::*, DeltaDbManagerTrait, DeltaDbTrait},
};
use parking_lot::Mutex;
use primitives::EpochId;
use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::Deref,
    sync::{Arc, Weak},
};
