// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::RwLock;
use std::{
    cmp,
    collections::{BinaryHeap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    parameters::light::{HEADER_REQUEST_TIMEOUT_MS, MAX_HEADERS_IN_FLIGHT},
    sync::SynchronizationGraph,
};
use cfx_types::H256;

// NOTE: order defines priority: Epoch < Reference < NewHash
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum HashSource {
    Epoch,     // hash received through an epoch request
    Reference, // hash referenced by a header we received
    NewHash,   // hash received through a new hashes announcement
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

#[derive(Debug)]
struct HeaderRequest {
    pub header: MissingHeader,
    pub sent_at: Instant,
}

impl HeaderRequest {
    pub fn new(header: MissingHeader) -> Self {
        HeaderRequest {
            header,
            sent_at: Instant::now(),
        }
    }
}

pub(super) struct Headers {
    // shared synchronization graph
    graph: Arc<SynchronizationGraph>,

    // headers requested but not received yet
    in_flight: RwLock<HashMap<H256, HeaderRequest>>,

    // priority queue of headers we need excluding the ones in `in_flight`
    waiting: RwLock<BinaryHeap<MissingHeader>>,
}

impl Headers {
    pub fn new(graph: Arc<SynchronizationGraph>) -> Self {
        Headers {
            graph,
            in_flight: RwLock::new(HashMap::new()),
            waiting: RwLock::new(BinaryHeap::new()),
        }
    }

    pub fn num_waiting(&self) -> usize { self.waiting.read().len() }

    pub fn num_in_flight(&self) -> usize { self.in_flight.read().len() }

    pub fn insert_in_flight<I>(&self, missing: I)
    where I: Iterator<Item = MissingHeader> {
        let new = missing.map(|h| (h.hash.clone(), HeaderRequest::new(h)));
        self.in_flight.write().extend(new);
    }

    pub fn remove_in_flight(&self, hash: &H256) {
        self.in_flight.write().remove(&hash);
    }

    pub fn insert_waiting<I>(&self, hashes: I, source: HashSource)
    where I: Iterator<Item = H256> {
        let headers = hashes.map(|h| MissingHeader::new(h, source.clone()));
        self.reinsert_waiting(headers);
    }

    pub fn reinsert_waiting<I>(&self, headers: I)
    where I: Iterator<Item = MissingHeader> {
        let in_flight = self.in_flight.read();
        let mut waiting = self.waiting.write();

        let missing = headers
            .filter(|h| !in_flight.contains_key(&h.hash))
            .filter(|h| !self.graph.contains_block_header(&h.hash));

        waiting.extend(missing);
    }

    pub fn collect_headers_to_request(&self) -> Vec<MissingHeader> {
        let in_flight = self.in_flight.read();
        let mut waiting = self.waiting.write();

        let num_to_request = MAX_HEADERS_IN_FLIGHT - in_flight.len();

        if num_to_request == 0 {
            return vec![];
        }

        let mut headers = vec![];

        // NOTE: cannot use iterator on BinaryHeap as
        // it returns elements in arbitrary order!
        while let Some(h) = waiting.pop() {
            if !in_flight.contains_key(&h.hash)
                && !self.graph.contains_block_header(&h.hash)
            {
                headers.push(h);
            }

            if headers.len() == num_to_request {
                break;
            }
        }

        headers
    }

    fn remove_timeout_requests(&self) -> Vec<MissingHeader> {
        let mut in_flight = self.in_flight.write();
        let timeout = Duration::from_millis(HEADER_REQUEST_TIMEOUT_MS);

        // collect timed-out requests
        let headers: Vec<_> = in_flight
            .iter()
            .filter_map(|(_hash, req)| match req.sent_at {
                t if t.elapsed() < timeout => None,
                _ => Some(req.header.clone()),
            })
            .collect();

        // remove requests from `in_flight`
        for h in &headers {
            in_flight.remove(&h.hash);
        }

        headers
    }

    pub fn clean_up(&self) {
        let headers = self.remove_timeout_requests();
        self.reinsert_waiting(headers.into_iter());
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
        assert!(HashSource::Epoch < HashSource::Reference);
        assert!(HashSource::Reference < HashSource::NewHash);

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
            source: HashSource::Reference,
        };

        assert!(h1 < h2); // higher source priority

        let h3 = MissingHeader {
            hash: 3.into(),
            since: one_ms_ago,
            source: HashSource::Reference,
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
            source: HashSource::Reference,
        };

        let h3 = MissingHeader {
            hash: 3.into(),
            since: one_ms_ago,
            source: HashSource::Reference,
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
