use std::{
    cmp::max,
    collections::{HashMap, HashSet},
};

const CACHE_INDEX_STRIDE: usize = 1000;
const MAX_ANTICONE_SIZE: usize = 300;

pub struct AnticoneCache {
    max_seen_index: usize,
    data: HashMap<usize, HashSet<usize>>,
}

impl AnticoneCache {
    pub fn new() -> Self {
        Self {
            max_seen_index: 0,
            data: HashMap::new(),
        }
    }

    pub fn update(&mut self, me: usize, anticone: &HashSet<usize>) {
        self.max_seen_index = max(self.max_seen_index, me);
        if anticone.len() < MAX_ANTICONE_SIZE {
            self.data.insert(me, anticone.clone());
        }
        if anticone.len() < self.data.len() {
            for index in anticone {
                if self.data.contains_key(index) {
                    let s = self.data.get_mut(index).unwrap();
                    s.insert(me);
                    if s.len() > MAX_ANTICONE_SIZE {
                        self.data.remove(index);
                    }
                }
            }
            if self.data.len() > 2 * CACHE_INDEX_STRIDE {
                let max_seen_index = self.max_seen_index;
                self.data
                    .retain(|k, _| (max_seen_index - *k <= CACHE_INDEX_STRIDE));
            }
        } else {
            let max_seen_index = self.max_seen_index;
            self.data.retain(|k, v| {
                if anticone.contains(k) {
                    v.insert(me);
                }
                (v.len() <= MAX_ANTICONE_SIZE)
                    && (max_seen_index - *k <= CACHE_INDEX_STRIDE)
            });
        }
    }

    pub fn get(&self, me: usize) -> Option<&HashSet<usize>> {
        self.data.get(&me)
    }
}
