// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::msgid;
use cfx_types::H256;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::HashSet;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Key {
    Hash(H256),
    Num(u64),
    Id(u32),
}

/// Common key container for all inflight requests. The supported message types
/// are all registered in the Default constructor.
pub struct KeyContainer {
    keys: Vec<Option<RwLock<HashSet<Key>>>>,
}

impl Default for KeyContainer {
    fn default() -> Self {
        let mut keys: Vec<Option<RwLock<HashSet<Key>>>> = Default::default();
        for _ in 0..256 {
            keys.push(None);
        }
        keys[msgid::GET_BLOCK_HASHES_BY_EPOCH as usize] =
            Some(Default::default());
        keys[msgid::GET_BLOCK_HEADERS as usize] = Some(Default::default());
        keys[msgid::GET_BLOCKS as usize] = Some(Default::default());
        keys[msgid::GET_TRANSACTIONS as usize] = Some(Default::default());
        keys[msgid::GET_TRANSACTIONS_FROM_TX_HASHES as usize] =
            Some(Default::default());

        KeyContainer { keys }
    }
}

impl KeyContainer {
    pub fn read(&self, msg_type: u8) -> RwLockReadGuard<HashSet<Key>> {
        self.keys[msg_type as usize]
            .as_ref()
            .expect("msg not supported")
            .read()
    }

    pub fn write(&self, msg_type: u8) -> RwLockWriteGuard<HashSet<Key>> {
        self.keys[msg_type as usize]
            .as_ref()
            .expect("msg not supported")
            .write()
    }

    pub fn add(&mut self, msg_type: u8, key: Key) -> bool {
        self.write(msg_type).insert(key)
    }

    pub fn remove(&mut self, msg_type: u8, key: Key) -> bool {
        self.write(msg_type).remove(&key)
    }
}
