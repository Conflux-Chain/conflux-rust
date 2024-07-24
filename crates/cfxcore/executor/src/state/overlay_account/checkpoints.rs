use std::collections::HashMap;

use crate::{
    state::checkpoints::{
        CheckpointEntry::{self, Recorded, Unchanged},
        CheckpointLayerTrait, LazyDiscardedVec,
    },
    unwrap_or_return,
};

use super::OverlayAccount;

#[derive(Debug)]
pub struct WriteCheckpointLayer<T: Clone> {
    storage_write: HashMap<Vec<u8>, CheckpointEntry<T>>,
    state_checkpoint_id: usize,
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

#[derive(Debug, Default)]
pub struct StorageWriteCache<T: Clone> {
    inner_cache: HashMap<Vec<u8>, T>,
    inner_checkpoints: LazyDiscardedVec<WriteCheckpointLayer<T>>,
}

impl<T: Clone> StorageWriteCache<T> {
    pub fn revert_checkpoints(&mut self, state_checkpoint_id: usize) {
        let last = unwrap_or_return!(self.inner_checkpoints.last_layer());
        let account_state_checkpoint_id = last.state_checkpoint_id;
        if account_state_checkpoint_id >= state_checkpoint_id {
            let revert_state_checkpoint_id =
                self.inner_checkpoints.revert_layer(&mut self.inner_cache);
            assert_eq!(
                revert_state_checkpoint_id,
                Some(account_state_checkpoint_id)
            );
        }
    }

    pub fn as_map(&mut self) -> &mut HashMap<Vec<u8>, T> {
        assert!(self.inner_checkpoints.is_empty());
        &mut self.inner_cache
    }

    pub fn get(&self, key: &[u8]) -> Option<&T> { self.inner_cache.get(key) }

    pub fn insert(&mut self, key: Vec<u8>, value: T) {
        let old_value = self.inner_cache.insert(key.clone(), value);
        self.inner_checkpoints
            .notify_element(key, CheckpointEntry::from_cache(old_value));
    }

    pub fn clear(&mut self) {
        self.inner_cache.clear();
        self.inner_checkpoints.clear();
    }

    pub fn drain(&mut self) -> impl '_ + Iterator<Item = (Vec<u8>, T)> {
        assert!(self.inner_checkpoints.is_empty());
        self.inner_cache.drain()
    }

    #[cfg(test)]
    pub fn cache_len(&self) -> usize { self.inner_cache.len() }

    #[cfg(test)]
    pub fn checkpoints_get(
        &self, key: &[u8], state_checkpoint_id: usize,
    ) -> Option<CheckpointEntry<T>> {
        let account_state_checkpoint_ids =
            self.inner_checkpoints.get_info_of_all_elements();
        let num_checkpoints = account_state_checkpoint_ids
            .iter()
            .rev()
            .take_while(|&&x| x >= state_checkpoint_id)
            .count();
        let start_checkpoint_index =
            account_state_checkpoint_ids.len() - num_checkpoints;
        for (relative_checkpoint_id, (account_checkpoint, _)) in self
            .inner_checkpoints
            .elements_from_index(start_checkpoint_index)
            .enumerate()
        {
            assert_eq!(
                account_checkpoint.state_checkpoint_id,
                account_state_checkpoint_ids
                    [start_checkpoint_index + relative_checkpoint_id]
            );
            if let Some(inner) = account_checkpoint.get(key) {
                return Some(inner);
            }
        }
        None
    }
}

impl OverlayAccount {
    pub fn add_checkpoint(&mut self, state_checkpoint_id: usize) {
        self.storage_write_cache
            .write()
            .inner_checkpoints
            .push_layer(WriteCheckpointLayer::new_empty(state_checkpoint_id));
        self.transient_storage
            .write()
            .inner_checkpoints
            .push_layer(WriteCheckpointLayer::new_empty(state_checkpoint_id));
    }

    pub fn clear_checkpoints(&mut self) {
        self.storage_write_cache.write().inner_checkpoints.clear();
        self.transient_storage.write().inner_checkpoints.clear();
    }

    pub fn revert_checkpoints(&mut self, state_checkpoint_id: usize) {
        self.storage_write_cache
            .write()
            .revert_checkpoints(state_checkpoint_id);
        self.transient_storage
            .write()
            .revert_checkpoints(state_checkpoint_id);
    }
}
