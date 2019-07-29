// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use std::collections::{HashMap, HashSet};

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Key {
    Hash(H256),
    Num(u64),
    Id(u32),
}

#[derive(Default)]
pub struct KeyContainer {
    keys: HashMap<u8, HashSet<Key>>,
}

impl KeyContainer {
    pub fn add(&mut self, msg_type: u8, key: Key) -> bool {
        self.keys
            .entry(msg_type)
            .or_insert_with(|| HashSet::new())
            .insert(key)
    }

    pub fn remove(&mut self, msg_type: u8, key: Key) -> bool {
        match self.keys.get_mut(&msg_type) {
            Some(keys) => keys.remove(&key),
            None => return false,
        }
    }

    pub fn len(&self, msg_type: u8) -> usize {
        match self.keys.get(&msg_type) {
            Some(keys) => keys.len(),
            None => 0,
        }
    }
}
