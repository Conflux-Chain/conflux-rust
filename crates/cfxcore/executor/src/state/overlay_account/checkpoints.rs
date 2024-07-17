use std::{collections::{hash_map::Entry, HashMap}, mem};

use primitives::StorageValue;

use crate::lazy_discarded_vec::{GetInfo, LazyDiscardedVec, OrInsert, Update};

use super::OverlayAccount;

#[derive(Debug)]
pub enum CheckpointStorageValue {
    Unchanged,
    Recorded(StorageValue),
}

impl CheckpointStorageValue {
    pub fn from_cache(v: Option<StorageValue>) -> Self {
        match v {
            Some(storage_value) => Self::Recorded(storage_value),
            None => Self::Unchanged,
        }
    }
}

#[derive(Debug)]
pub struct WriteCheckpointLayer {
    storage_write: HashMap<Vec<u8>, CheckpointStorageValue>,
    state_checkpoint_id: usize,
}

impl WriteCheckpointLayer {
    fn new_empty(state_checkpoint_id: usize) -> Self {
        Self {
            storage_write: HashMap::new(),
            state_checkpoint_id
        }
    }
}

impl OrInsert<Vec<u8>, CheckpointStorageValue> for WriteCheckpointLayer {
    fn entry_or_insert(&mut self, key: Vec<u8>, value: CheckpointStorageValue) -> bool {
        self.storage_write.entry_or_insert(key, value)
    }
}

impl Update<HashMap<Vec<u8>, StorageValue>> for WriteCheckpointLayer {
    fn update(self, cache: &mut HashMap<Vec<u8>, StorageValue>) {
        for (k, v) in self.storage_write.into_iter() {
            match v {
                CheckpointStorageValue::Unchanged => cache.remove(&k),
                CheckpointStorageValue::Recorded(storage_value) => cache.insert(k, storage_value),
            };
        }
    }
}

impl GetInfo<usize> for WriteCheckpointLayer {
    fn get_additional_info(&self) -> usize {
        self.state_checkpoint_id
    }
}

#[derive(Debug, Default)]
pub struct StorageWriteCache {
    storage_write_cache: HashMap<Vec<u8>, StorageValue>,
    storage_write_checkpoints: LazyDiscardedVec<Vec<u8>, CheckpointStorageValue, HashMap<Vec<u8>, StorageValue>, usize, WriteCheckpointLayer>,
}

impl StorageWriteCache {
    pub fn insert_write_cache(&mut self, key: Vec<u8>, value: StorageValue) {
        let old_value = self.storage_write_cache.insert(key.clone(), value);
        self.storage_write_checkpoints.notify_last_element(key, CheckpointStorageValue::from_cache(old_value));
    }
    pub fn notify_checkpoint(&mut self, key: Vec<u8>, old_value: CheckpointStorageValue) {
        self.storage_write_checkpoints.notify_last_element(key, old_value);
    }
    pub fn entry(&mut self, key: Vec<u8>) -> Entry<'_, Vec<u8>, StorageValue> {
        self.storage_write_cache.entry(key)
    }
    pub fn clear_cache(&mut self) {
        for (k, v) in self.storage_write_cache.drain() {
            self.storage_write_checkpoints.notify_last_element(k, CheckpointStorageValue::Recorded(v));
        }
    }
    pub fn cache_get(&self, key: &[u8]) -> Option<&StorageValue> {
        self.storage_write_cache.get(key)
    }
    pub fn cache_iter_mut(&mut self) -> std::collections::hash_map::IterMut<Vec<u8>, StorageValue> {
        self.storage_write_cache.iter_mut()
    }
    pub fn drain_cache(&mut self) -> HashMap<Vec<u8>, StorageValue> {
        mem::take(&mut self.storage_write_cache)
    }
    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        self.storage_write_cache.len()
    }
}

impl OverlayAccount {
    pub fn add_checkpoint(&mut self, state_checkpoint_id: usize) {
        self.storage_write_cache.write().storage_write_checkpoints.add_element(WriteCheckpointLayer::new_empty(state_checkpoint_id));
    }
}