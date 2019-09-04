// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use futures::{Async, Future, Poll};
use parking_lot::RwLock;
use std::{collections::HashMap, hash::Hash, sync::Arc};

use crate::light_protocol::Error;

pub struct FutureItem<K, V> {
    key: K,
    verified: Arc<RwLock<HashMap<K, V>>>,
}

impl<K, V> FutureItem<K, V> {
    pub fn new(
        key: K, verified: Arc<RwLock<HashMap<K, V>>>,
    ) -> FutureItem<K, V> {
        FutureItem { key, verified }
    }
}

impl<K, V> Future for FutureItem<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    type Error = Error;
    type Item = V;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.verified.read().get(&self.key) {
            None => Ok(Async::NotReady),
            Some(item) => Ok(Async::Ready(item.clone())),
        }
    }
}
