// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

pub enum PendingItem<T> {
    Ready(T),
    Pending(Vec<Waker>),
}

impl<T> PendingItem<T> {
    pub fn pending() -> PendingItem<T> { Self::Pending(vec![]) }

    pub fn ready(item: T) -> PendingItem<T> { Self::Ready(item) }
}

impl<T> PendingItem<T> {
    // NOTE: `set` has to be called in a thread-safe environment
    pub fn set(&mut self, item: T) {
        match self {
            Self::Ready(_old) => {
                // FIXME: we might want to check if old == item and raise an
                // error if not. This, however, would require that T : Eq.
                // This should not happen unless there are deep chain reorgs.
            }
            Self::Pending(ws) => {
                // move `ws` out
                let ws = std::mem::replace(ws, Vec::<Waker>::new());

                // transform `self`
                *self = Self::Ready(item);

                // notify waiting futures
                for w in ws {
                    w.wake();
                }
            }
        }
    }
}

impl<T: Clone> PendingItem<T> {
    // NOTE: `poll` has to be called in a thread-safe environment
    fn poll(&mut self, ctx: &mut Context) -> Poll<T> {
        match self {
            Self::Ready(item) => Poll::Ready(item.clone()),
            Self::Pending(ws) => {
                // FIXME: is it safe to keep old wakers?
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
