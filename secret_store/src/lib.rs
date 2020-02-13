// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate ethkey as keylib;
extern crate parking_lot;

use keylib::KeyPair;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

pub struct StoreInner {
    account_vec: Vec<KeyPair>,
    secret_map: HashMap<String, usize>,
}

impl StoreInner {
    pub fn new() -> Self {
        StoreInner {
            account_vec: Vec::new(),
            secret_map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, kp: KeyPair) -> bool {
        let secret_string = kp.secret().to_hex();
        if self.secret_map.contains_key(&secret_string) {
            return false;
        }

        let index = self.count();
        self.secret_map.insert(secret_string, index);
        self.account_vec.push(kp);
        true
    }

    pub fn count(&self) -> usize { self.account_vec.len() }

    pub fn get_keypair(&self, index: usize) -> KeyPair {
        self.account_vec[index].clone()
    }

    pub fn remove_keypair(&mut self, index: usize) {
        let secret_string = self.account_vec[index].secret().to_hex();
        self.secret_map.remove(&secret_string);
        self.account_vec.remove(index);
    }
}

pub struct SecretStore {
    store: RwLock<StoreInner>,
}

pub type SharedSecretStore = Arc<SecretStore>;

impl SecretStore {
    pub fn new() -> Self {
        SecretStore {
            store: RwLock::new(StoreInner::new()),
        }
    }

    pub fn insert(&self, kp: KeyPair) -> bool { self.store.write().insert(kp) }

    pub fn count(&self) -> usize { self.store.read().count() }

    pub fn get_keypair(&self, index: usize) -> KeyPair {
        self.store.read().get_keypair(index)
    }

    pub fn remove_keypair(&self, index: usize) {
        self.store.write().remove_keypair(index);
    }
}
