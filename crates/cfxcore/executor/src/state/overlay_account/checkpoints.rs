use std::{collections::{hash_map::Entry, HashMap}, mem};

use crate::{lazy_discarded_vec::{GetInfo, LazyDiscardedVec, OrInsert, Update}, unwrap_or_return};

use super::OverlayAccount;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub enum CheckpointStorageValue<T: Clone> {
    Unchanged,
    Recorded(T),
}

impl<T: Clone> CheckpointStorageValue<T> {
    pub fn from_cache(v: Option<T>) -> Self {
        match v {
            Some(storage_value) => Self::Recorded(storage_value),
            None => Self::Unchanged,
        }
    }
    #[cfg(test)]
    pub fn into_cache(self) -> Option<T> {
        match self {
            Self::Recorded(storage_value) => Some(storage_value),
            Self::Unchanged => None
        }
    }
}

#[derive(Debug)]
pub struct WriteCheckpointLayer<T: Clone> {
    storage_write: HashMap<Vec<u8>, CheckpointStorageValue<T>>,
    state_checkpoint_id: usize,
}

impl<T: Clone> WriteCheckpointLayer<T> {
    fn new_empty(state_checkpoint_id: usize) -> Self {
        Self {
            storage_write: HashMap::new(),
            state_checkpoint_id
        }
    }

    #[cfg(test)]
    pub fn get(&self, key: &[u8]) -> Option<CheckpointStorageValue<T>> {
        self.storage_write.get(key).cloned()
    }
}

impl<T: Clone> OrInsert<Vec<u8>, CheckpointStorageValue<T>> for WriteCheckpointLayer<T> {
    fn entry_or_insert(&mut self, key: Vec<u8>, value: CheckpointStorageValue<T>) -> bool {
        self.storage_write.entry_or_insert(key, value)
    }
}

impl<T: Clone> Update<HashMap<Vec<u8>, T>> for WriteCheckpointLayer<T> {
    fn update(self, cache: &mut HashMap<Vec<u8>, T>, _self_id: usize) {
        for (k, v) in self.storage_write.into_iter() {
            match v {
                CheckpointStorageValue::Unchanged => cache.remove(&k),
                CheckpointStorageValue::Recorded(storage_value) => cache.insert(k, storage_value),
            };
        }
    }
}

impl<T: Clone> GetInfo<usize> for WriteCheckpointLayer<T> {
    fn get_additional_info(&self) -> usize {
        self.state_checkpoint_id
    }
}

#[derive(Debug, Default)]
pub struct StorageWriteCache<T: Clone> {
    inner_cache: HashMap<Vec<u8>, T>,
    inner_checkpoints: LazyDiscardedVec<Vec<u8>, CheckpointStorageValue<T>, HashMap<Vec<u8>, T>, usize, WriteCheckpointLayer<T>>,
}

impl<T: Clone> StorageWriteCache<T> {
    pub fn revert_checkpoints(&mut self, state_checkpoint_id: usize) {
        let account_state_checkpoint_id = unwrap_or_return!(self.inner_checkpoints.get_info_of_last_element());
        if account_state_checkpoint_id >= state_checkpoint_id {
            let revert_state_checkpoint_id = self.inner_checkpoints.revert_element(&mut self.inner_cache);
            assert_eq!(revert_state_checkpoint_id, Some(account_state_checkpoint_id));
        }
    }
    pub fn cache_insert(&mut self, key: Vec<u8>, value: T) {
        let old_value = self.inner_cache.insert(key.clone(), value);
        self.inner_checkpoints.notify_last_element(key, CheckpointStorageValue::from_cache(old_value));
    }
    pub fn notify_checkpoint(&mut self, key: Vec<u8>, old_value: CheckpointStorageValue<T>) {
        self.inner_checkpoints.notify_last_element(key, old_value);
    }
    pub fn cache_entry(&mut self, key: Vec<u8>) -> Entry<'_, Vec<u8>, T> {
        self.inner_cache.entry(key)
    }
    pub fn clear_cache(&mut self) {
        for (k, v) in self.inner_cache.drain() {
            self.inner_checkpoints.notify_last_element(k, CheckpointStorageValue::Recorded(v));
        }
    }
    pub fn cache_get(&self, key: &[u8]) -> Option<&T> {
        self.inner_cache.get(key)
    }
    pub fn cache_iter_mut(&mut self) -> std::collections::hash_map::IterMut<Vec<u8>, T> {
        self.inner_cache.iter_mut()
    }
    pub fn drain_cache(&mut self) -> HashMap<Vec<u8>, T> {
        mem::take(&mut self.inner_cache)
    }
    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        self.inner_cache.len()
    }
    #[cfg(test)]
    pub fn checkpoints_get(&self, key: &[u8], state_checkpoint_id: usize) -> Option<CheckpointStorageValue<T>> {
        let account_state_checkpoint_ids = self.inner_checkpoints.get_info_of_all_elements();
        let num_checkpoints = account_state_checkpoint_ids.iter()
            .rev()
            .take_while(|&&x| x >= state_checkpoint_id)
            .count();
        let start_checkpoint_index = account_state_checkpoint_ids.len() - num_checkpoints;
        for (relative_checkpoint_id, (account_checkpoint, _)) in self.inner_checkpoints.elements_from_index(start_checkpoint_index).enumerate() {
            assert_eq!(account_checkpoint.state_checkpoint_id, account_state_checkpoint_ids[start_checkpoint_index + relative_checkpoint_id]);
            if let Some(inner) = account_checkpoint.get(key) {
                return Some(inner)
            }
        }
        None
    }
}

impl OverlayAccount {
    pub fn add_checkpoint(&mut self, state_checkpoint_id: usize) {
        self.storage_write_cache.write().inner_checkpoints.add_element(WriteCheckpointLayer::new_empty(state_checkpoint_id));
        self.transient_storage.write().inner_checkpoints.add_element(WriteCheckpointLayer::new_empty(state_checkpoint_id));
    }

    pub fn clear_checkpoints(&mut self) {
        self.storage_write_cache.write().inner_checkpoints.clear_elements();
        self.transient_storage.write().inner_checkpoints.clear_elements();
    }

    pub fn revert_checkpoints(&mut self, state_checkpoint_id: usize) {
        self.storage_write_cache.write().revert_checkpoints(state_checkpoint_id);
        self.transient_storage.write().revert_checkpoints(state_checkpoint_id);
    }
}