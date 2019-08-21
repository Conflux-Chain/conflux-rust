// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use hibitset::BitSet;
use std::collections::{HashMap, HashSet};

const MAX_PASTSET_CACHE_CAP: usize = 256;

#[derive(Default)]
pub struct PastSetCache {
    cache: HashMap<usize, (BitSet, u64)>,
    entry: u64,
}

impl PastSetCache {
    pub fn update(&mut self, me: usize, pastset: BitSet) {
        if self.cache.len() == MAX_PASTSET_CACHE_CAP {
            let mut evict = 0;
            let mut min_entry = self.entry;
            for (index, (_, entry)) in self.cache.iter() {
                if *entry < min_entry {
                    min_entry = *entry;
                    evict = *index;
                }
            }
            assert!(min_entry != self.entry);
            self.cache.remove(&evict);
        }
        self.cache.insert(me, (pastset, self.entry));
        self.entry += 1;
    }

    pub fn get(&mut self, me: usize, update_cache: bool) -> Option<&BitSet> {
        if let Some(v) = self.cache.get_mut(&me) {
            if update_cache {
                v.1 = self.entry;
                self.entry += 1;
            }
            Some(&v.0)
        } else {
            None
        }
    }

    pub fn intersect_update(&mut self, outside_era_blockset: &HashSet<usize>) {
        self.cache.retain(|me, (s, _)| {
            if outside_era_blockset.contains(me) {
                false
            } else {
                for index in outside_era_blockset.iter() {
                    s.remove(*index as u32);
                }
                true
            }
        });
    }
}
