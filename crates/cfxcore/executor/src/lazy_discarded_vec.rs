use std::{hash::Hash, collections::HashMap, marker::PhantomData};

pub trait Update<P> {
    fn update(self, cache: &mut P, self_id: usize);
}

pub trait GetInfo<S> {
    fn get_additional_info(&self) -> S;
}

pub trait OrInsert<K, V> {
    fn entry_or_insert(&mut self, key: K, value: V) -> bool;
}

impl<K: PartialEq + Eq + Hash, V> OrInsert<K, V> for HashMap<K, V> {
    fn entry_or_insert(&mut self, key: K, value: V) -> bool {
        let entry = self.entry(key);
        match entry {
            std::collections::hash_map::Entry::Occupied(_) => {
                false
            },
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(value);
                true
            }
        }
    }
}

#[derive(Debug)]
pub struct LazyDiscardedVec<K, V, P, S, T: OrInsert<K, V> + Update<P>> {
    inner_vec: Vec<T>,
    last_undiscard_indices: Vec<usize>,
    num_undiscard_elements: usize,
    _phantom: PhantomData<(K, V, P, S)>
}

impl<K, V, P, S, T: OrInsert<K, V> + Update<P> + GetInfo<S>> Default for LazyDiscardedVec<K, V, P, S, T> {
    fn default() -> Self {
        Self {
            inner_vec: Default::default(), 
            last_undiscard_indices: Default::default(), 
            num_undiscard_elements: Default::default(), 
            _phantom: Default::default()
        }
    }
}

impl<K, V, P, S, T: OrInsert<K, V> + Update<P> + GetInfo<S>> LazyDiscardedVec<K, V, P, S, T> {
    pub fn is_empty(&self) -> bool {
        self.num_undiscard_elements == 0
    }

    pub fn add_element(&mut self, new_element: T) -> usize {
        let current_index = self.last_undiscard_indices.len();
        self.last_undiscard_indices.push(current_index);
        self.inner_vec.push(new_element);
        self.num_undiscard_elements += 1;
        self.num_undiscard_elements - 1
    }

    pub fn clear_elements(&mut self) {
        self.inner_vec = Vec::new();
        self.last_undiscard_indices = Vec::new();
        self.num_undiscard_elements = 0;
    }

    pub fn discard_element(&mut self, clear_empty: bool) -> Option<usize> {
        let num_elements = self.inner_vec.len();
        if num_elements > 0 {
            let current_discard_index = self.last_undiscard_indices[num_elements - 1];
            if current_discard_index == 0 {
                if clear_empty {
                    self.inner_vec = Vec::new();
                    self.last_undiscard_indices = Vec::new();
                }
                assert_eq!(self.num_undiscard_elements, 1);
            }
            else {
                self.last_undiscard_indices[num_elements - 1] = self.last_undiscard_indices[current_discard_index - 1];
                assert!(self.num_undiscard_elements > 1);
            }
            self.num_undiscard_elements -= 1;
            Some(current_discard_index)
        }
        else {
            None
        }
    }

    pub fn revert_element(&mut self, cache: &mut P) -> Option<S> {
        let current_discard_index = self.discard_element(false)?;
        let last_element_id = self.last_undiscard_indices.len() - 1;
        assert!(current_discard_index <= last_element_id);
        self.last_undiscard_indices.truncate(current_discard_index);
        let revert_elements = self.inner_vec.split_off(current_discard_index);
        let additional_info = revert_elements[0].get_additional_info();
        for (id_from_last, one_revert_element) in revert_elements.into_iter().rev().enumerate() {
            one_revert_element.update(cache, last_element_id - id_from_last);
        }
        Some(additional_info)
    }

    pub fn get_info_of_last_element(&self) -> Option<S> {
        if self.num_undiscard_elements == 0 {
            assert_eq!(self.inner_vec.len(), 0);
            return None
        }

        Some(self.inner_vec.last().unwrap().get_additional_info())
    }

    #[cfg(test)]
    pub fn get_info_of_all_elements(&self) -> Vec<S> {
        self.inner_vec.iter().map(|element| element.get_additional_info()).collect()
    }

    pub fn notify_last_element(&mut self, key: K, value: V) -> Option<Option<usize>> {
        if self.num_undiscard_elements == 0 {
            assert_eq!(self.inner_vec.len(), 0);
            return None
        }

        let last_element = self.inner_vec.last_mut().unwrap();
        let update = last_element.entry_or_insert(key, value);
        if update {
            Some(Some(self.inner_vec.len() - 1))
        }
        else {
            Some(None)
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.num_undiscard_elements
    }

    #[cfg(test)]
    pub fn elements_from_index(
        &self, undiscard_element_index: usize)
    -> impl Iterator<Item=(&T, usize)> {
        let mut element_index = self.last_undiscard_indices.len();
        if undiscard_element_index < self.num_undiscard_elements {
            for _ in (undiscard_element_index..self.num_undiscard_elements).rev() {
                element_index = self.last_undiscard_indices[element_index - 1];
            }
        }
        self.inner_vec.iter().skip(element_index).zip(element_index..self.last_undiscard_indices.len())
    }
}
