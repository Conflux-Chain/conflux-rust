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
    inner: Option<Arc<dyn DeltaDbTrait>>,
    lru: Option<Weak<Mutex<dyn OnDemandOpenDeltaDbTrait>>>,
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
            let maybe_arc_db = mem::replace(&mut self.inner, None);
            drop(maybe_arc_db);
            lru_lock.release(self.mpt_id, false);
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

pub trait OnDemandOpenDeltaDbTrait: Send + Sync {
    fn open(&mut self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper>;
    fn create(
        &mut self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
    ) -> Result<ArcDeltaDbWrapper>;
    fn release(&mut self, mpt_id: DeltaMptId, destroy: bool);
}

pub struct OpenDeltaDbLru {
    inner: Arc<Mutex<dyn OnDemandOpenDeltaDbTrait>>,
}

impl OpenDeltaDbLru {
    pub fn new<T: DeltaDbManagerTrait + 'static + Send + Sync>(
        delta_db_manager: Arc<T>,
    ) -> Result<Self>
    where T::DeltaDb: 'static + Send + Sync {
        Ok(Self {
            inner: Arc::new(Mutex::new(OpenDeltaDbLruInner::<T>::new(
                delta_db_manager,
            )?)),
        })
    }

    pub fn open(&self, mpt_id: DeltaMptId) -> Result<ArcDeltaDbWrapper> {
        let mut arc_db = self.inner.lock().open(mpt_id).unwrap();
        arc_db.lru = Some(Arc::downgrade(&self.inner));
        Ok(arc_db)
    }

    pub fn create(
        &self, snapshot_epoch_id: &EpochId, mpt_id: DeltaMptId,
    ) -> Result<ArcDeltaDbWrapper> {
        let mut arc_db =
            self.inner.lock().create(snapshot_epoch_id, mpt_id).unwrap();
        arc_db.lru = Some(Arc::downgrade(&self.inner));
        Ok(arc_db)
    }

    pub fn release(&self, mpt_id: DeltaMptId, destroy: bool) {
        self.inner.lock().release(mpt_id, destroy);
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

impl<T: DeltaDbManagerTrait + Send + Sync> OnDemandOpenDeltaDbTrait
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
    ) -> Result<ArcDeltaDbWrapper> {
        match self.mpt_id_to_snapshot_epoch_id.get(&mpt_id) {
            Some(epoch_id) => {
                assert_eq!(snapshot_epoch_id, epoch_id);
                self.open(mpt_id)
            }
            None => {
                self.mpt_id_to_snapshot_epoch_id
                    .insert(mpt_id, snapshot_epoch_id.clone());
                let arc_db = Arc::new(
                    self.delta_db_manager.new_empty_delta_db(
                        &self
                            .delta_db_manager
                            .get_delta_db_name(snapshot_epoch_id),
                    )?,
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

    fn release(&mut self, mpt_id: DeltaMptId, destroy: bool) {
        match self.cache_util.cache_data.get(&mpt_id) {
            Some(tuple) => {
                let strong_count = Arc::strong_count(&tuple.0);
                if destroy {
                    assert_eq!(strong_count, 1);
                }
                if destroy || (strong_count == 1 && !tuple.1.is_hit()) {
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
    mem,
    ops::Deref,
    sync::{Arc, Weak},
};
