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

#[cfg(test)]
mod tests {
    use super::{FutureItem, PendingItem};
    use futures::future::join3;
    use lru_time_cache::LruCache;
    use parking_lot::RwLock;
    use std::{sync::Arc, time::Duration};
    use tokio::{runtime::Runtime, time::delay_for};

    #[test]
    fn test_concurrent_access() {
        const KEY: u64 = 1;
        const VALUE: u64 = 2;
        const DELAY: u64 = 10;

        let cache = LruCache::<u64, PendingItem<u64>>::with_capacity(1);
        let verified = Arc::new(RwLock::new(cache));

        // we will simulate 3 concurrent accesses to the same item
        let item1 = FutureItem::new(KEY, verified.clone());
        let item2 = FutureItem::new(KEY, verified.clone());
        let item3 = FutureItem::new(KEY, verified.clone());

        // request item once
        let fut1 = async move { item1.await };

        // request item, wait, then request again
        let fut2 = async move {
            let res2 = item2.await;
            delay_for(Duration::from_millis(2 * DELAY)).await;
            let res3 = item3.await;
            (res2, res3)
        };

        // wait, then provide item
        let fut3 = async move {
            delay_for(Duration::from_millis(DELAY)).await;

            verified
                .write()
                .entry(KEY)
                .or_insert(PendingItem::pending())
                .set(VALUE);
        };

        let mut runtime = Runtime::new().expect("Unable to create a runtime");
        let (res1, (res2, res3), _) = runtime.block_on(join3(fut1, fut2, fut3));

        assert_eq!(res1, VALUE);
        assert_eq!(res2, VALUE);
        assert_eq!(res3, VALUE);
    }
}
