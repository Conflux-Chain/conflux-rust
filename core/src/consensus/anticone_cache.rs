use hibitset::{BitSet, BitSetLike};
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

    pub fn update(&mut self, me: usize, anticone: &BitSet) {
        self.max_seen_index = max(self.max_seen_index, me);
        // BitSet does not have len() method
        if anticone.len() < MAX_ANTICONE_SIZE {
            let mut tmp = HashSet::new();
            for index in anticone.iter() {
                tmp.insert(index as usize);
            }
            self.data.insert(me, tmp);
        }

        if anticone.len() < self.data.len() {
            for index in anticone.iter() {
                let index_usize = index as usize;
                if self.data.contains_key(&index_usize) {
                    let s = self.data.get_mut(&index_usize).unwrap();
                    s.insert(me);
                    if s.len() > MAX_ANTICONE_SIZE {
                        self.data.remove(&index_usize);
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
                if anticone.contains(*k as u32) {
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
