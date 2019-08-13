// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Key {
    Hash(H256),
    Num(u64),
    Id(u32),
}

#[derive(Default)]
pub struct KeyContainer {
    keys: RwLock<HashMap<u8, Arc<RwLock<HashSet<Key>>>>>,
}

impl KeyContainer {
    fn get(&self, msg_type: u8) -> Option<Arc<RwLock<HashSet<Key>>>> {
        let keys = self.keys.read();
        keys.get(&msg_type).cloned()
    }

    pub fn get_or_insert(&self, msg_type: u8) -> Arc<RwLock<HashSet<Key>>> {
        let mut keys = self.keys.write();
        keys.entry(msg_type)
            .or_insert_with(|| Default::default())
            .clone()
    }

    pub fn add(&mut self, msg_type: u8, key: Key) -> bool {
        self.get_or_insert(msg_type).write().insert(key)
    }

    pub fn remove(&mut self, msg_type: u8, key: Key) -> bool {
        self.get_or_insert(msg_type).write().remove(&key)
    }

    pub fn len(&self, msg_type: u8) -> usize {
        match self.get(msg_type) {
            Some(keys) => keys.read().len(),
            None => 0,
        }
    }
}
