use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use super::CheckpointEntry;

pub trait CheckpointLayerTrait {
    type Key: Eq + Hash + Clone;
    type Value;
    type ExtInfo;

    fn get_additional_info(&self) -> Self::ExtInfo;

    fn as_hash_map(
        &mut self,
    ) -> &mut HashMap<Self::Key, CheckpointEntry<Self::Value>>;

    fn update(
        self, cache: &mut HashMap<Self::Key, Self::Value>, self_id: usize,
    );

    fn insert_on_absent(
        &mut self, key: Self::Key, value: CheckpointEntry<Self::Value>,
    ) -> bool {
        use std::collections::hash_map::Entry::*;
        match self.as_hash_map().entry(key) {
            Occupied(_) => false,
            Vacant(e) => {
                e.insert(value);
                true
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LazyDiscardedVec<T: CheckpointLayerTrait> {
    inner_vec: Vec<T>,
    undiscard_indices: Vec<usize>,
}

impl<T: CheckpointLayerTrait> Default for LazyDiscardedVec<T> {
    fn default() -> Self {
        Self {
            inner_vec: Default::default(),
            undiscard_indices: Default::default(),
        }
    }
}

impl<T: CheckpointLayerTrait> LazyDiscardedVec<T> {
    #[inline]
    fn total_len(&self) -> usize { self.inner_vec.len() }

    pub fn last_layer_id(&self) -> usize { self.inner_vec.len() }

    pub fn is_empty(&self) -> bool {
        if self.undiscard_indices.is_empty() {
            assert!(self.inner_vec.is_empty());
            true
        } else {
            false
        }
    }

    pub fn push_layer(&mut self, new_element: T) -> usize {
        self.undiscard_indices.push(self.total_len());
        self.inner_vec.push(new_element);
        self.undiscard_indices.len() - 1
    }

    pub fn discard_layer(&mut self) -> Option<HashSet<T::Key>> {
        self.undiscard_indices.pop()?;

        let mut cleared_keys = HashSet::default();

        if self.undiscard_indices.is_empty() {
            cleared_keys = self
                .inner_vec
                .iter_mut()
                .flat_map(|x| x.as_hash_map().keys())
                .cloned()
                .collect();
            self.clear();
        }
        Some(cleared_keys)
    }

    fn pop_lazy_discarded_layers(&mut self) -> Option<(usize, Vec<T>)> {
        let index = self.undiscard_indices.pop()?;
        assert!(index < self.total_len());
        let reverted_layers = self.inner_vec.split_off(index);
        Some((index, reverted_layers))
    }

    pub fn revert_layer(
        &mut self, cache: &mut HashMap<T::Key, T::Value>,
    ) -> Option<T::ExtInfo> {
        let last_layer_id = self.total_len() - 1;
        let (first_layer_id, reverted_layers) =
            self.pop_lazy_discarded_layers()?;

        let additional_info = reverted_layers[0].get_additional_info();
        for (id, one_revert_element) in (first_layer_id..=last_layer_id)
            .rev()
            .zip(reverted_layers.into_iter().rev())
        {
            one_revert_element.update(cache, id);
        }

        Some(additional_info)
    }

    pub fn last_layer(&self) -> Option<&T> { self.inner_vec.last() }

    pub fn notify_element(
        &mut self, key: T::Key, value: CheckpointEntry<T::Value>,
    ) -> bool {
        if self.is_empty() {
            return false;
        }

        let last_element = self.inner_vec.last_mut().unwrap();
        last_element.insert_on_absent(key, value)
    }

    pub fn clear(&mut self) {
        self.inner_vec.clear();
        self.undiscard_indices.clear();
    }

    #[cfg(test)]
    fn undiscarded_len(&self) -> usize { self.undiscard_indices.len() }

    #[cfg(test)]
    pub fn get_info_of_all_elements(&self) -> Vec<T::ExtInfo> {
        self.inner_vec
            .iter()
            .map(|element| element.get_additional_info())
            .collect()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.undiscarded_len() }

    #[cfg(test)]
    pub fn elements_from_index(
        &self, undiscard_element_index: usize,
    ) -> impl Iterator<Item = (&T, usize)> {
        let mut element_index = self.undiscard_indices.len();
        if undiscard_element_index < self.undiscarded_len() {
            for _ in (undiscard_element_index..self.undiscarded_len()).rev() {
                element_index = self.undiscard_indices[element_index - 1];
            }
        }
        self.inner_vec
            .iter()
            .skip(element_index)
            .zip(element_index..self.total_len())
    }
}
