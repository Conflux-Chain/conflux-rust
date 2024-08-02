use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use super::CheckpointEntry;

pub trait CheckpointLayerTrait {
    type Key: Eq + Hash + Clone;
    type Value;

    fn as_hash_map(&self) -> &HashMap<Self::Key, CheckpointEntry<Self::Value>>;

    fn as_hash_map_mut(
        &mut self,
    ) -> &mut HashMap<Self::Key, CheckpointEntry<Self::Value>>;
}

#[derive(Debug, Clone)]
pub struct LazyDiscardedVec<T: CheckpointLayerTrait> {
    inner_vec: Vec<T>,
    bundle_start_indices: Vec<usize>,
}

impl<T: CheckpointLayerTrait> Default for LazyDiscardedVec<T> {
    fn default() -> Self {
        Self {
            inner_vec: Default::default(),
            bundle_start_indices: Default::default(),
        }
    }
}

impl<T: CheckpointLayerTrait> LazyDiscardedVec<T> {
    fn total_len(&self) -> usize { self.inner_vec.len() }

    pub fn is_empty(&self) -> bool {
        if self.bundle_start_indices.is_empty() {
            assert!(self.inner_vec.is_empty());
            true
        } else {
            false
        }
    }

    pub fn push_checkpoint(&mut self, new_element: T) -> usize {
        self.bundle_start_indices.push(self.total_len());
        self.inner_vec.push(new_element);
        self.bundle_start_indices.len() - 1
    }

    pub fn discard_checkpoint(&mut self) -> Option<HashSet<T::Key>> {
        self.bundle_start_indices.pop()?;

        if self.bundle_start_indices.is_empty() {
            Some(self.discard_all_checkpoints())
        } else {
            None
        }
    }

    fn discard_all_checkpoints(&mut self) -> HashSet<T::Key> {
        let cleared_keys = self
            .inner_vec
            .iter()
            .flat_map(|x| x.as_hash_map().keys())
            .cloned()
            .collect();
        self.clear();
        cleared_keys
    }

    pub fn revert_to_checkpoint(
        &mut self,
    ) -> Option<impl Iterator<Item = (usize, T)>> {
        let first_layer_id = self.bundle_start_indices.pop()?;
        assert!(first_layer_id < self.total_len());
        let last_layer_id = self.total_len() - 1;

        let reverted_layers = self.inner_vec.split_off(first_layer_id);

        Some(
            (first_layer_id..=last_layer_id)
                .rev()
                .zip(reverted_layers.into_iter().rev()),
        )
    }

    pub fn clear(&mut self) {
        self.inner_vec.clear();
        self.bundle_start_indices.clear();
    }

    pub fn insert_element(
        &mut self, key: T::Key,
        value: impl FnOnce(usize) -> CheckpointEntry<T::Value>,
    ) {
        if self.is_empty() {
            return;
        }

        let last_layer_id = self.inner_vec.len() - 1;
        let last_element = self.inner_vec.last_mut().unwrap();
        last_element
            .as_hash_map_mut()
            .entry(key)
            .or_insert_with(|| value(last_layer_id));
    }

    #[cfg(test)]
    fn undiscarded_len(&self) -> usize { self.bundle_start_indices.len() }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.undiscarded_len() }

    #[cfg(test)]
    pub fn elements_from_index(
        &self, undiscard_element_index: usize,
    ) -> impl Iterator<Item = &T> {
        let element_index = if undiscard_element_index < self.undiscarded_len()
        {
            self.bundle_start_indices[undiscard_element_index]
        } else {
            self.total_len()
        };
        self.inner_vec.iter().skip(element_index)
    }
}
