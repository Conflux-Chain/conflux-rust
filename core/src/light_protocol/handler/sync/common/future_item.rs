// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;
extern crate lru_time_cache;

use futures::{Async, Future, Poll};
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{hash::Hash, sync::Arc};

use crate::light_protocol::Error;

pub struct FutureItem<K, V> {
    key: K,
    verified: Arc<RwLock<LruCache<K, V>>>,
}

impl<K, V> FutureItem<K, V> {
    pub fn new(
        key: K, verified: Arc<RwLock<LruCache<K, V>>>,
    ) -> FutureItem<K, V> {
        FutureItem { key, verified }
    }
}

impl<K, V> Future for FutureItem<K, V>
where
    K: Clone + Eq + Hash + Ord,
    V: Clone,
{
    type Error = Error;
    type Item = V;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.verified.write().get(&self.key) {
            None => Ok(Async::NotReady),
            Some(item) => Ok(Async::Ready(item.clone())),
        }
    }
}
