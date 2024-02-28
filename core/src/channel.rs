// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::UniqueId;
use cfx_types::H256;
use parking_lot::RwLock;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio02::{runtime, sync::mpsc, time::timeout};

pub use tokio02::{sync::mpsc::error::TryRecvError, time::Elapsed};

pub struct Receiver<T> {
    pub id: u64,
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> Receiver<T> {
    pub async fn recv(&mut self) -> Option<T> { self.receiver.recv().await }

    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn recv_blocking(&mut self) -> Option<T> {
        futures::executor::block_on(self.receiver.recv())
    }

    pub fn recv_with_timeout(
        &mut self, wait_for: Duration,
    ) -> Result<Option<T>, Elapsed> {
        runtime::Builder::new()
            .basic_scheduler()
            .enable_time()
            .build()
            .expect("Runtime can be created")
            // this only works in an async block, see:
            // https://users.rust-lang.org/t/tokio-interval-not-working-in-runtime/41260/2
            .block_on(
                async move { timeout(wait_for, self.receiver.recv()).await },
            )
    }

    // NOTE: do not capture anything in `f` that might have references to
    // `Notifications`, otherwise the loop might never terminate.
    pub async fn for_each(mut self, f: impl Fn(T) -> ()) {
        while let Some(t) = self.recv().await {
            f(t);
        }
    }
}

/// Implements an unbounded MPMC broadcast channel.
pub struct Channel<T> {
    // Used for generating subscription ids unique to this channel.
    id_allocator: UniqueId,

    // Name of the current instance.
    name: String,

    // Set of subscriptions, represented as ID => Sender pairs.
    subscriptions: RwLock<BTreeMap<u64, mpsc::UnboundedSender<T>>>,
}

impl<T: Clone> Channel<T> {
    pub fn new(name: &str) -> Self {
        Self {
            id_allocator: UniqueId::new(),
            name: name.to_owned(),
            subscriptions: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn subscribe(&self) -> Receiver<T> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = self.id_allocator.next();
        self.subscriptions.write().insert(id, sender);
        Receiver { id, receiver }
    }

    pub fn unsubscribe(&self, id: u64) -> bool {
        self.subscriptions.write().remove(&id).is_some()
    }

    pub fn num_subscriptions(&self) -> usize { self.subscriptions.read().len() }

    pub fn send(&self, t: T) -> bool {
        let mut sent = false;
        let mut invalid = vec![];

        for (id, send) in &*self.subscriptions.write() {
            match send.send(t.clone()) {
                Ok(_) => sent = true,
                Err(_e) => {
                    warn!(
                        "Channel {}::{} dropped without unsubscribe",
                        self.name, id
                    );
                    invalid.push(*id);
                }
            }
        }

        for id in invalid {
            self.unsubscribe(id);
        }

        sent
    }
}

pub struct Notifications {
    pub new_block_hashes: Arc<Channel<H256>>,
    pub epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>,
    pub blame_verification_results: Arc<Channel<(u64, Option<u64>)>>, /* <height, witness> */
    pub new_pending_transactions: Arc<Channel<H256>>,
}

impl Notifications {
    pub fn init() -> Arc<Self> {
        Arc::new(Notifications {
            new_block_hashes: Arc::new(Channel::new("new-block-hashes")),
            epochs_ordered: Arc::new(Channel::new("epochs-executed")),
            blame_verification_results: Arc::new(Channel::new(
                "blame-verification-results",
            )),
            new_pending_transactions: Arc::new(Channel::new("new-pending-transactions")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Channel;
    use futures::future::join3;
    use rand::Rng;
    use tokio::runtime::Runtime;

    #[test]
    fn test_sync() {
        let chan = Channel::<u64>::new("test-chan");

        // try send without subscribers
        let sent = chan.send(1001);
        assert!(!sent);

        // add one subscription
        let mut rec1 = chan.subscribe();
        assert_eq!(chan.num_subscriptions(), 1);

        let sent = chan.send(1002);
        assert!(sent);

        assert_eq!(rec1.recv_blocking(), Some(1002));

        // add one subscription
        let mut rec2 = chan.subscribe();
        assert_eq!(chan.num_subscriptions(), 2);

        let sent = chan.send(1003);
        assert!(sent);
        let sent = chan.send(1004);
        assert!(sent);

        assert_eq!(rec1.recv_blocking(), Some(1003));
        assert_eq!(rec1.recv_blocking(), Some(1004));
        assert_eq!(rec2.recv_blocking(), Some(1003));
        assert_eq!(rec2.recv_blocking(), Some(1004));

        // unsubscribe first
        assert!(chan.unsubscribe(rec1.id));
        assert_eq!(chan.num_subscriptions(), 1);

        let sent = chan.send(1005);
        assert!(sent);

        assert_eq!(rec2.recv_blocking(), Some(1005));

        // unsubscribe second
        assert!(chan.unsubscribe(rec2.id));
        assert_eq!(chan.num_subscriptions(), 0);

        let sent = chan.send(1005);
        assert!(!sent);
    }

    #[test]
    fn test_drop_receivers() {
        let chan = Channel::<u64>::new("test-chan");

        // add subscriptions
        let rec1 = chan.subscribe();
        let mut rec2 = chan.subscribe();

        // drop first
        drop(rec1);
        assert_eq!(chan.num_subscriptions(), 2);

        let sent = chan.send(1004);
        assert!(sent);
        assert_eq!(chan.num_subscriptions(), 1);

        assert_eq!(rec2.recv_blocking(), Some(1004));

        // drop second
        drop(rec2);
        assert_eq!(chan.num_subscriptions(), 1);

        let sent = chan.send(1005);
        assert!(!sent);
        assert_eq!(chan.num_subscriptions(), 0);
    }

    #[test]
    fn test_drop_sender() {
        // create channel add subscriptions
        let chan = Channel::<u64>::new("test-chan");
        let mut rec1 = chan.subscribe();
        let mut rec2 = chan.subscribe();

        // send normally
        let sent = chan.send(1001);
        assert!(sent);

        assert_eq!(rec1.recv_blocking(), Some(1001));
        assert_eq!(rec2.recv_blocking(), Some(1001));

        // drop sender
        drop(chan);

        assert_eq!(rec1.recv_blocking(), None);
        assert_eq!(rec2.recv_blocking(), None);
    }

    #[test]
    fn test_async() {
        // create channel add subscriptions
        let chan = Channel::<u64>::new("test-chan");
        let mut rec1 = chan.subscribe();
        let mut rec2 = chan.subscribe();

        // create async receiver
        let fut1 = async move {
            let mut received = vec![];
            while let Some(t) = rec1.recv().await {
                received.push(t);
            }
            received
        };

        // create async receiver
        let fut2 = async move {
            let mut received = vec![];
            while let Some(t) = rec2.recv().await {
                received.push(t);
            }
            received
        };

        // create async sender
        let fut3 = async move {
            let mut rng = rand::thread_rng();
            let mut sent = vec![];
            for t in (0..100).map(|_| rng.gen()) {
                chan.send(t);
                sent.push(t);
            }
            sent
        };

        let runtime = Runtime::new().expect("Unable to create a runtime");
        let (res1, res2, res3) = runtime.block_on(join3(fut1, fut2, fut3));

        assert_eq!(res1, res3);
        assert_eq!(res2, res3);
    }

    #[test]
    fn test_ring() {
        // create channels and add subscriptions
        let send_a = Channel::<u64>::new("test-chan-ab");
        let send_b = Channel::<u64>::new("test-chan-bc");
        let send_c = Channel::<u64>::new("test-chan-ca");

        let mut rec_b = send_a.subscribe();
        let mut rec_c = send_b.subscribe();
        let mut rec_a = send_c.subscribe();

        // create async sender
        let fut_a = async move {
            let mut rng = rand::thread_rng();

            for t in (0..100).map(|_| rng.gen()) {
                send_a.send(t);
                let t2 = rec_a.recv().await;

                if t2 != Some(t) {
                    return Err(format!("Not equal: {:?}, {:?}", t2, Some(t)));
                }
            }

            Ok(())
        };

        // create async receiver
        let fut_b = async move {
            while let Some(t) = rec_b.recv().await {
                send_b.send(t);
            }
        };

        // create async receiver
        let fut_c = async move {
            while let Some(t) = rec_c.recv().await {
                send_c.send(t);
            }
        };

        let runtime = Runtime::new().expect("Unable to create a runtime");
        let (res, (), ()) = runtime.block_on(join3(fut_a, fut_b, fut_c));
        assert_eq!(res, Ok(()))
    }
}
