use std::{collections::HashMap, fmt::Debug, hash::Hash};

use cfx_types::U256;
use primitives::StorageValue;

use crate::{
    state::checkpoints::CheckpointEntry::{self, Recorded, Unchanged},
    unwrap_or_return,
};

use super::OverlayAccount;

#[derive(Debug, Clone)]
pub struct WriteCheckpointLayer<K: Hash + Clone + Eq, T: Clone> {
    storage_write: HashMap<K, CheckpointEntry<T>>,
    state_checkpoint_id: usize,
}

impl<K: Hash + Clone + Eq, T: Clone> Default for WriteCheckpointLayer<K, T> {
    fn default() -> Self {
        Self {
            storage_write: Default::default(),
            state_checkpoint_id: Default::default(),
        }
    }
}

impl<K: Hash + Clone + Eq, T: Clone> WriteCheckpointLayer<K, T> {
    pub(super) fn new_empty(state_checkpoint_id: usize) -> Self {
        Self {
            storage_write: HashMap::new(),
            state_checkpoint_id,
        }
    }

    fn revert_checkpoint(
        self, state_checkpoint_id: usize, cache: &mut HashMap<K, T>,
    ) {
        if self.state_checkpoint_id >= state_checkpoint_id {
            for (k, v) in self.storage_write.into_iter() {
                match v {
                    Unchanged => cache.remove(&k),
                    Recorded(storage_value) => cache.insert(k, storage_value),
                };
            }
        }
    }

    fn notify_cache_change(&mut self, key: K, old_value: Option<T>) {
        self.storage_write
            .entry(key)
            .or_insert(CheckpointEntry::from_cache(old_value));
    }

    #[cfg(test)]
    pub fn get_state_cp_id(&self) -> usize { self.state_checkpoint_id }

    #[cfg(test)]
    pub fn get<Q: ?Sized + Hash + Eq>(
        &self, key: &Q,
    ) -> Option<CheckpointEntry<T>>
    where K: std::borrow::Borrow<Q> {
        self.storage_write.get(key).cloned()
    }
}

impl OverlayAccount {
    pub(super) fn insert_storage_write_cache(
        &mut self, key: Vec<u8>, value: StorageValue,
    ) {
        let old_value =
            self.storage_write_cache.write().insert(key.clone(), value);
        unwrap_or_return!(self.storage_write_checkpoint.as_mut())
            .notify_cache_change(key, old_value);
    }

    pub(super) fn insert_transient_write_cache(
        &mut self, key: Vec<u8>, value: U256,
    ) {
        let old_value = self
            .transient_storage_cache
            .write()
            .insert(key.clone(), value);
        unwrap_or_return!(self.transient_storage_checkpoint.as_mut())
            .notify_cache_change(key, old_value);
    }

    pub fn clear_checkpoint(&mut self) {
        self.storage_write_checkpoint = None;
        self.transient_storage_checkpoint = None;
    }

    pub fn revert_checkpoint(&mut self, state_checkpoint_id: usize) {
        if let Some(ct) = self.storage_write_checkpoint.take() {
            ct.revert_checkpoint(
                state_checkpoint_id,
                &mut self.storage_write_cache.write(),
            )
        };

        if let Some(ct) = self.transient_storage_checkpoint.take() {
            ct.revert_checkpoint(
                state_checkpoint_id,
                &mut self.transient_storage_cache.write(),
            )
        };
    }
}

impl OverlayAccount {
    #[cfg(test)]
    pub fn eq_write_cache(&self, other: &Self) -> bool {
        use std::sync::Arc;

        Arc::ptr_eq(&self.storage_write_cache, &other.storage_write_cache)
    }
}
