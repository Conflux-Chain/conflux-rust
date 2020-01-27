// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{hash::Hash, sync::Arc};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use crate::light_protocol::Error;

pub enum ItemOrWaker<T> {
    Item(T),
    Waker(Waker),
}

pub struct FutureItem<K, V> {
    key: K,
    verified: Arc<RwLock<LruCache<K, ItemOrWaker<V>>>>,
}

impl<K, V> FutureItem<K, V> {
    pub fn new(
        key: K, verified: Arc<RwLock<LruCache<K, ItemOrWaker<V>>>>,
    ) -> FutureItem<K, V> {
        FutureItem { key, verified }
    }
}

impl<K, V> Future for FutureItem<K, V>
where
    K: Clone + Eq + Hash + Ord,
    V: Clone,
{
    type Output = V;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let mut verified = self.verified.write();

        match verified.get(&self.key) {
            Some(ItemOrWaker::Item(i)) => Poll::Ready(i.clone()),
            _ => {
                verified.insert(self.key.clone(), ItemOrWaker::Waker(context.waker().clone()));
                Poll::Pending
            }
        }
    }
}
