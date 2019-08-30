// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    cmp,
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    light_protocol::{
        common::{Peers, UniqueId},
        handler::FullPeerState,
        message::GetBlockHeaders,
        Error,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        HEADER_REQUEST_BATCH_SIZE, HEADER_REQUEST_TIMEOUT_MS,
        MAX_HEADERS_IN_FLIGHT,
    },
    sync::SynchronizationGraph,
};

use super::sync_manager::{HasKey, SyncManager};
use cfx_types::H256;
use primitives::BlockHeader;

#[derive(Debug)]
struct Statistics {
    duplicate_count: u64,
    in_flight: usize,
    waiting: usize,
}

// NOTE: order defines priority: Epoch < Reference < NewHash
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum HashSource {
    Epoch,      // hash received through an epoch request
    Dependency, // hash referenced by a header we received
    NewHash,    // hash received through a new hashes announcement
}

#[derive(Clone, Debug, Eq)]
pub(super) struct MissingHeader {
    pub hash: H256,
    pub since: Instant,
    pub source: HashSource,
}

impl MissingHeader {
    pub fn new(hash: H256, source: HashSource) -> Self {
        MissingHeader {
            hash,
            since: Instant::now(),
            source,
        }
    }
}

impl PartialEq for MissingHeader {
    fn eq(&self, other: &Self) -> bool { self.hash == other.hash }
}

// MissingHeader::cmp is used for prioritizing header requests
impl Ord for MissingHeader {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self.eq(other) {
            return cmp::Ordering::Equal;
        }

        let cmp_source = self.source.cmp(&other.source);
        let cmp_since = self.since.cmp(&other.since).reverse();
        let cmp_hash = self.hash.cmp(&other.hash);

        cmp_source.then(cmp_since).then(cmp_hash)
    }
}

impl PartialOrd for MissingHeader {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl HasKey<H256> for MissingHeader {
    fn key(&self) -> H256 { self.hash }
}

pub(super) struct Headers {
    // number of headers received multiple times
    duplicate_count: AtomicU64,

    // shared synchronization graph
    graph: Arc<SynchronizationGraph>,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingHeader>,
}

impl Headers {
    pub fn new(
        graph: Arc<SynchronizationGraph>, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let duplicate_count = AtomicU64::new(0);
        let sync_manager = SyncManager::new(peers.clone());

        Headers {
            duplicate_count,
            graph,
            sync_manager,
            request_id_allocator,
        }
    }

    #[inline]
    pub fn num_waiting(&self) -> usize { self.sync_manager.num_waiting() }

    #[inline]
    fn get_statistics(&self) -> Statistics {
        Statistics {
            duplicate_count: self.duplicate_count.load(Ordering::Relaxed),
            in_flight: self.sync_manager.num_in_flight(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    #[inline]
    pub fn request<I>(&self, hashes: I, source: HashSource)
    where I: Iterator<Item = H256> {
        let headers = hashes
            .filter(|h| !self.graph.contains_block_header(&h))
            .map(|h| MissingHeader::new(h, source.clone()));

        self.sync_manager.insert_waiting(headers);
    }

    pub fn receive<I>(&self, headers: I)
    where I: Iterator<Item = BlockHeader> {
        let mut missing = HashSet::new();

        // TODO(thegaram): validate header timestamps
        for header in headers {
            let hash = header.hash();

            // signal receipt
            self.sync_manager.remove_in_flight(&hash);

            // check duplicates
            if self.graph.contains_block_header(&hash) {
                self.duplicate_count.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // insert into graph
            let (valid, _) = self.graph.insert_block_header(
                &mut header.clone(),
                true,  /* need_to_verify */
                false, /* bench_mode */
                true,  /* insert_to_consensus */
                true,  /* persistent */
            );

            if !valid {
                continue;
            }

            // store missing dependencies
            missing.insert(*header.parent_hash());

            for referee in header.referee_hashes() {
                missing.insert(*referee);
            }
        }

        let missing = missing.into_iter();
        self.request(missing, HashSource::Dependency);
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = Duration::from_millis(HEADER_REQUEST_TIMEOUT_MS);
        let headers = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(headers.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetBlockHeaders {
            request_id: self.request_id_allocator.next(),
            hashes,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("header sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_HEADERS_IN_FLIGHT,
            HEADER_REQUEST_BATCH_SIZE,
            |peer, hashes| self.send_request(io, peer, hashes),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{HashSource, MissingHeader};
    use rand::Rng;
    use std::{
        collections::BinaryHeap,
        ops::Sub,
        time::{Duration, Instant},
    };

    #[test]
    fn test_ordering() {
        assert!(HashSource::Epoch < HashSource::Dependency);
        assert!(HashSource::Dependency < HashSource::NewHash);

        let now = Instant::now();
        let one_ms_ago = now.sub(Duration::from_millis(1));

        let h0 = MissingHeader {
            hash: 0.into(),
            since: now,
            source: HashSource::Epoch,
        };

        let h1 = MissingHeader {
            hash: 1.into(),
            since: one_ms_ago,
            source: HashSource::Epoch,
        };

        assert!(h0 < h1); // longer waiting time

        let h2 = MissingHeader {
            hash: 2.into(),
            since: now,
            source: HashSource::Dependency,
        };

        assert!(h1 < h2); // higher source priority

        let h3 = MissingHeader {
            hash: 3.into(),
            since: one_ms_ago,
            source: HashSource::Dependency,
        };

        assert!(h2 < h3); // longer waiting time

        let h4 = MissingHeader {
            hash: 4.into(),
            since: now,
            source: HashSource::NewHash,
        };

        assert!(h3 < h4); // higher source priority

        let h5 = MissingHeader {
            hash: 5.into(),
            since: one_ms_ago,
            source: HashSource::NewHash,
        };

        assert!(h4 < h5); // longer waiting time

        let h6 = MissingHeader {
            hash: 6.into(),
            since: now,
            source: HashSource::NewHash,
        };

        assert!(h4 < h6); // hash order

        let h7 = MissingHeader {
            hash: 6.into(),
            since: one_ms_ago,
            source: HashSource::Epoch,
        };

        assert_eq!(h6, h7); // identical hash
    }

    fn assert_deep_equal(h1: Option<MissingHeader>, h2: Option<MissingHeader>) {
        // MissingHeader::eq only considers the hash; here we check all fields
        assert_eq!(h1.clone().map(|h| h.hash), h2.clone().map(|h| h.hash));
        assert_eq!(h1.clone().map(|h| h.since), h2.clone().map(|h| h.since));
        assert_eq!(h1.clone().map(|h| h.source), h2.clone().map(|h| h.source));
    }

    #[test]
    fn test_queue() {
        let now = Instant::now();
        let one_ms_ago = now.sub(Duration::from_millis(1));

        let h0 = MissingHeader {
            hash: 0.into(),
            since: now,
            source: HashSource::Epoch,
        };

        let h1 = MissingHeader {
            hash: 1.into(),
            since: one_ms_ago,
            source: HashSource::Epoch,
        };

        let h2 = MissingHeader {
            hash: 2.into(),
            since: now,
            source: HashSource::Dependency,
        };

        let h3 = MissingHeader {
            hash: 3.into(),
            since: one_ms_ago,
            source: HashSource::Dependency,
        };

        let h4 = MissingHeader {
            hash: 4.into(),
            since: now,
            source: HashSource::NewHash,
        };

        let h5 = MissingHeader {
            hash: 5.into(),
            since: one_ms_ago,
            source: HashSource::NewHash,
        };

        let h6 = MissingHeader {
            hash: 5.into(),
            since: one_ms_ago,
            source: HashSource::NewHash,
        };

        let mut headers = vec![];
        headers.push(h0.clone());
        headers.push(h1.clone());
        headers.push(h2.clone());
        headers.push(h3.clone());
        headers.push(h4.clone());
        headers.push(h5.clone());
        headers.push(h6.clone());

        // NOTE: as `h5.hash == h6.hash`, BinaryHeap will
        // insert another instance of `h5` in the last step;
        // this is not optimal, but we have other checks to
        // to ensure we don't request headers multiple times

        rand::thread_rng().shuffle(&mut headers);
        let mut queue: BinaryHeap<MissingHeader> = BinaryHeap::new();
        queue.extend(headers);

        assert_deep_equal(queue.pop(), Some(h5.clone()));
        assert_deep_equal(queue.pop(), Some(h5));
        assert_deep_equal(queue.pop(), Some(h4));
        assert_deep_equal(queue.pop(), Some(h3));
        assert_deep_equal(queue.pop(), Some(h2));
        assert_deep_equal(queue.pop(), Some(h1));
        assert_deep_equal(queue.pop(), Some(h0));
        assert_deep_equal(queue.pop(), None);
    }
}
