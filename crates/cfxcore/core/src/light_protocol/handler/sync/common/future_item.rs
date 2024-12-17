// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

pub enum PendingItem<Item, Err> {
    Ready(Item),
    Pending(Vec<Waker>),
    Error(Err),
}

impl<Item, Err> PendingItem<Item, Err> {
    pub fn pending() -> Self { Self::Pending(vec![]) }

    pub fn ready(item: Item) -> Self { Self::Ready(item) }

    pub fn clear_error(&mut self) {
        if let Self::Error(_) = self {
            *self = Self::pending();
        }
    }

    // NOTE: `set` has to be called in a thread-safe environment
    pub fn set(&mut self, item: Item) {
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
            Self::Error(_) => {
                // if we managed to verify the item, we do not care about the
                // error anymore. wakers must have been notified when `self` was
                // set to `Error`, so they either received an error or haven't
                // polled yet.
                *self = Self::Ready(item);
            }
        }
    }

    // NOTE: `set_error` has to be called in a thread-safe environment
    pub fn set_error(&mut self, err: Err) {
        match self {
            Self::Ready(_) => {
                // if we already have a verified value, we do not care about
                // errors anymore
            }
            Self::Pending(ws) => {
                // move `ws` out
                let ws = std::mem::replace(ws, Vec::<Waker>::new());

                // transform `self`
                *self = Self::Error(err);

                // notify waiting futures
                for w in ws {
                    w.wake();
                }
            }
            Self::Error(_) => {
                *self = Self::Error(err);
            }
        }
    }
}

impl<Item: Clone, Err: Clone> PendingItem<Item, Err> {
    // NOTE: `poll` has to be called in a thread-safe environment
    fn poll(&mut self, ctx: &mut Context) -> Poll<Result<Item, Err>> {
        match self {
            Self::Ready(item) => Poll::Ready(Ok(item.clone())),
            Self::Pending(ws) => {
                // FIXME: is it safe to keep old wakers?
                ws.push(ctx.waker().clone());
                Poll::Pending
            }
            Self::Error(e) => Poll::Ready(Err(e.clone())),
        }
    }
}

pub struct FutureItem<K, V, E> {
    key: K,
    verified: Arc<RwLock<LruCache<K, PendingItem<V, E>>>>,
}

impl<K, V, E> FutureItem<K, V, E> {
    pub fn new(
        key: K, verified: Arc<RwLock<LruCache<K, PendingItem<V, E>>>>,
    ) -> FutureItem<K, V, E> {
        FutureItem { key, verified }
    }
}

impl<K, V, E> Future for FutureItem<K, V, E>
where
    K: Clone + Eq + Hash + Ord,
    V: Clone,
    E: Clone,
{
    type Output = Result<V, E>;

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
    use tokio::{runtime::Runtime, time::sleep};

    #[test]
    fn test_set() {
        const KEY: u64 = 1;
        const VALUE: u64 = 2;
        const ERROR: u64 = 3;

        let cache = LruCache::<u64, PendingItem<u64, u64>>::with_capacity(1);
        let verified = Arc::new(RwLock::new(cache));

        let runtime = Runtime::new().expect("Unable to create a runtime");

        // set error
        verified
            .write()
            .entry(KEY)
            .or_insert(PendingItem::pending())
            .set_error(ERROR);

        // caller should get the error
        let res = runtime.block_on(FutureItem::new(KEY, verified.clone()));
        assert_eq!(res, Err(ERROR));

        // set value
        verified
            .write()
            .entry(KEY)
            .or_insert(PendingItem::pending())
            .set(VALUE);

        // caller should get the value
        let res = runtime.block_on(FutureItem::new(KEY, verified.clone()));
        assert_eq!(res, Ok(VALUE));

        // set error again
        verified
            .write()
            .entry(KEY)
            .or_insert(PendingItem::pending())
            .set_error(ERROR);

        // result is not overwritten by error
        let res = runtime.block_on(FutureItem::new(KEY, verified.clone()));
        assert_eq!(res, Ok(VALUE));
    }

    #[test]
    fn test_concurrent_access() {
        const KEY: u64 = 1;
        const VALUE: u64 = 2;
        const DELAY: u64 = 10;

        let cache = LruCache::<u64, PendingItem<u64, ()>>::with_capacity(1);
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
            sleep(Duration::from_millis(2 * DELAY)).await;
            let res3 = item3.await;
            (res2, res3)
        };

        // wait, then provide item
        let fut3 = async move {
            sleep(Duration::from_millis(DELAY)).await;

            verified
                .write()
                .entry(KEY)
                .or_insert(PendingItem::pending())
                .set(VALUE);
        };

        let runtime = Runtime::new().expect("Unable to create a runtime");
        let (res1, (res2, res3), _) = runtime.block_on(join3(fut1, fut2, fut3));

        assert_eq!(res1, Ok(VALUE));
        assert_eq!(res2, Ok(VALUE));
        assert_eq!(res3, Ok(VALUE));
    }
}
