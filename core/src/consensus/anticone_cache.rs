// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use hibitset::{BitSet, BitSetLike};
use std::{
    cmp::max,
    collections::{HashMap, HashSet},
};

const CACHE_INDEX_STRIDE: usize = 1000;
const MAX_ANTICONE_SIZE: usize = 300;

/// AnticoneCache keeps only the anticone set of the recent CACHE_INDEX_STRIDE
/// blocks. It also removes a block anticone set from it if the set is larger
/// than MAX_ANTICONE_SIZE
pub struct AnticoneCache {
    max_seen_index: usize,
    seq_number: u64,
    data: HashMap<usize, (HashSet<usize>, u64)>,
}

impl AnticoneCache {
    pub fn new() -> Self {
        Self {
            max_seen_index: 0,
            seq_number: 0,
            data: HashMap::new(),
        }
    }

    pub fn update(&mut self, me: usize, anticone: &BitSet) {
        self.seq_number += 1;
        self.max_seen_index = max(self.max_seen_index, me);
        // BitSet does not have len() method
        if anticone.len() < MAX_ANTICONE_SIZE {
            let mut tmp = HashSet::new();
            for index in anticone.iter() {
                tmp.insert(index as usize);
            }
            self.data.insert(me, (tmp, self.seq_number));
        }

        if anticone.len() < self.data.len() {
            for index in anticone.iter() {
                let index_usize = index as usize;
                if self.data.contains_key(&index_usize) {
                    let s = &mut self.data.get_mut(&index_usize).unwrap().0;
                    s.insert(me);
                    if s.len() > MAX_ANTICONE_SIZE {
                        self.data.remove(&index_usize);
                    }
                }
            }
            if self.data.len() > 2 * CACHE_INDEX_STRIDE {
                let seq_number = self.seq_number;
                self.data.retain(|_, (_, k)| {
                    seq_number - *k <= CACHE_INDEX_STRIDE as u64
                });
            }
        } else {
            let seq_number = self.seq_number;
            self.data.retain(|k, v| {
                if anticone.contains(*k as u32) {
                    v.0.insert(me);
                }
                (v.0.len() <= MAX_ANTICONE_SIZE)
                    && (seq_number - v.1 <= CACHE_INDEX_STRIDE as u64)
            });
        }
    }

    pub fn get(&self, me: usize) -> Option<&HashSet<usize>> {
        if let Some(v) = self.data.get(&me) {
            Some(&v.0)
        } else {
            None
        }
    }

    pub fn intersect_update(&mut self, era_blockset: &HashSet<usize>) {
        let seq_number = self.seq_number;
        self.data.retain(|_, (s, seq)| {
            s.retain(|v| era_blockset.contains(v));
            seq_number - *seq <= CACHE_INDEX_STRIDE as u64
        });
    }
}
