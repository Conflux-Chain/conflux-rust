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

pub enum PendingItem<T> {
    Ready(T),
    Pending(Vec<Waker>),
}

impl<T> PendingItem<T> {
    pub fn pending() -> PendingItem<T> {
        Self::Pending(vec![])
    }

    pub fn ready(item: T) -> PendingItem<T> {
        Self::Ready(item)
    }

    pub fn set(&mut self, item: T) {
        match self {
            Self::Ready(old) => {
                // TODO: check if same
            }
            Self::Pending(ws) => {
                // let mut wakers = Vec::<Waker>::new();
                // std::mem::swap(ws, &mut wakers);
                let ws = std::mem::replace(ws, Vec::<Waker>::new());

                *self = Self::Ready(item);

                for w in ws {
                    w.wake_by_ref();
                }
            }
        }
    }
}

impl<T> PendingItem<T> where T: Clone {
    fn poll(&mut self, ctx: &mut Context) -> Poll<T> {
        match self {
            Self::Ready(item) => Poll::Ready(item.clone()),
            Self::Pending(ws) => {
                ws.push(ctx.waker().clone());
                Poll::Pending
            }
        }
    }
}

pub struct FutureItem<K, V> {
    key: K,
    verified: Arc<RwLock<LruCache<K, PendingItem<V>>>>,
}

impl<K, V> FutureItem<K, V> {
    pub fn new(
        key: K, verified: Arc<RwLock<LruCache<K, PendingItem<V>>>>,
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

    fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        self.verified
            .write()
            .entry(self.key.clone())
            .or_insert(PendingItem::pending())
            .poll(ctx)
    }
}
