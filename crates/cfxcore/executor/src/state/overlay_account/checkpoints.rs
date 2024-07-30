use std::{collections::HashMap, fmt::Debug};

use crate::state::checkpoints::{
    CheckpointEntry::{self, Recorded, Unchanged},
    CheckpointLayerTrait,
};

use super::OverlayAccount;

#[derive(Debug, Clone)]
pub struct WriteCheckpointLayer<T: Clone> {
    storage_write: HashMap<Vec<u8>, CheckpointEntry<T>>,
    state_checkpoint_id: usize,
}

impl<T: Clone> WriteCheckpointLayer<T> {
    #[cfg(test)]
    pub fn get_state_cp_id(&self) -> usize { self.state_checkpoint_id }
}

impl<T: Clone> Default for WriteCheckpointLayer<T> {
    fn default() -> Self {
        Self {
            storage_write: Default::default(),
            state_checkpoint_id: Default::default(),
        }
    }
}

impl<T: Clone> WriteCheckpointLayer<T> {
    fn new_empty(state_checkpoint_id: usize) -> Self {
        Self {
            storage_write: HashMap::new(),
            state_checkpoint_id,
        }
    }

    #[cfg(test)]
    pub fn get(&self, key: &[u8]) -> Option<CheckpointEntry<T>> {
        self.storage_write.get(key).cloned()
    }
}

impl<T: Clone> CheckpointLayerTrait for WriteCheckpointLayer<T> {
    type ExtInfo = usize;
    type Key = Vec<u8>;
    type Value = T;

    fn get_additional_info(&self) -> Self::ExtInfo { self.state_checkpoint_id }

    fn as_hash_map(
        &mut self,
    ) -> &mut HashMap<Self::Key, CheckpointEntry<Self::Value>> {
        &mut self.storage_write
    }

    fn update(
        self, cache: &mut HashMap<Self::Key, Self::Value>, _self_id: usize,
    ) {
        for (k, v) in self.storage_write.into_iter() {
            match v {
                Unchanged => cache.remove(&k),
                Recorded(storage_value) => cache.insert(k, storage_value),
            };
        }
    }
}

pub fn revert_checkpoint<T: Clone>(
    checkpoint: Option<WriteCheckpointLayer<T>>, state_checkpoint_id: usize,
    cache: &mut HashMap<Vec<u8>, T>,
) {
    if checkpoint.is_none() {
        return ();
    }
    let last = checkpoint.unwrap();
    let account_state_checkpoint_id = last.state_checkpoint_id;
    if account_state_checkpoint_id >= state_checkpoint_id {
        last.update(cache, 0);
    }
}

#[derive(Debug, Default)]
pub struct StorageWriteCache<T: Clone> {
    inner_cache: HashMap<Vec<u8>, T>,
    inner_checkpoint: Option<WriteCheckpointLayer<T>>,
}

impl<T: Clone> StorageWriteCache<T> {
    pub fn revert_checkpoint(&mut self, state_checkpoint_id: usize) {
        if self.inner_checkpoint.is_none() {
            return ();
        }
        let last = self.inner_checkpoint.take().unwrap();
        let account_state_checkpoint_id = last.state_checkpoint_id;
        if account_state_checkpoint_id >= state_checkpoint_id {
            last.update(&mut self.inner_cache, 0);
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&T> { self.inner_cache.get(key) }

    pub fn insert(&mut self, key: Vec<u8>, value: T) {
        let old_value = self.inner_cache.insert(key.clone(), value);
        if self.inner_checkpoint.is_none() {
            return ();
        }
        let last = self.inner_checkpoint.as_mut().unwrap();
        last.insert_on_absent(key, CheckpointEntry::from_cache(old_value));
    }
}

pub fn insert_and_notify<T: Clone + std::fmt::Debug>(
    key: Vec<u8>, value: T, cache: &mut HashMap<Vec<u8>, T>,
    checkpoint: &mut Option<WriteCheckpointLayer<T>>,
) {
    let old_value = cache.insert(key.clone(), value);
    if checkpoint.is_none() {
        return ();
    }
    let last = checkpoint.as_mut().unwrap();
    last.insert_on_absent(key, CheckpointEntry::from_cache(old_value));
}

impl OverlayAccount {
    pub fn set_checkpoint(&mut self, state_checkpoint_id: usize) {
        self.storage_write_checkpoint =
            Some(WriteCheckpointLayer::new_empty(state_checkpoint_id));
        self.transient_storage.write().inner_checkpoint =
            Some(WriteCheckpointLayer::new_empty(state_checkpoint_id));
    }

    pub fn clear_checkpoint(&mut self) {
        self.storage_write_checkpoint = None;
        self.transient_storage.write().inner_checkpoint = None;
    }

    pub fn revert_checkpoint(&mut self, state_checkpoint_id: usize) {
        revert_checkpoint(
            self.storage_write_checkpoint.take(),
            state_checkpoint_id,
            &mut self.storage_write_cache.write(),
        );
        self.transient_storage
            .write()
            .revert_checkpoint(state_checkpoint_id);
    }
}

impl OverlayAccount {
    #[cfg(test)]
    pub fn eq_write_cache(&self, other: &Self) -> bool {
        use std::sync::Arc;

        Arc::ptr_eq(&self.storage_write_cache, &other.storage_write_cache)
    }
}
