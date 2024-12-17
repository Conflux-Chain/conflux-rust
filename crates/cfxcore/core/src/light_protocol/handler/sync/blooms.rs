// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::Bloom;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{future::Future, sync::Arc};

use super::{
    common::{FutureItem, KeyOrdered, PendingItem, SyncManager},
    witnesses::Witnesses,
};
use crate::{
    hash::keccak,
    light_protocol::{
        common::{FullPeerState, Peers},
        error::*,
        message::{msgid, BloomWithEpoch, GetBlooms},
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::light::{
    BLOOM_REQUEST_BATCH_SIZE, BLOOM_REQUEST_TIMEOUT, CACHE_TIMEOUT,
    MAX_BLOOMS_IN_FLIGHT,
};
use futures::future::FutureExt;
use network::{node_table::NodeId, NetworkContext};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize higher epochs
type MissingBloom = KeyOrdered<u64>;

type PendingBloom = PendingItem<Bloom, ClonableError>;

pub struct Blooms {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingBloom>,

    // bloom filters received from full node
    verified: Arc<RwLock<LruCache<u64, PendingBloom>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl Blooms {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        witnesses: Arc<Witnesses>,
    ) -> Self {
        let sync_manager = SyncManager::new(peers.clone(), msgid::GET_BLOOMS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        Blooms {
            request_id_allocator,
            sync_manager,
            verified,
            witnesses,
        }
    }

    #[inline]
    pub fn print_stats(&self) {
        debug!(
            "bloom sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    #[inline]
    pub fn request(&self, epoch: u64) -> impl Future<Output = Result<Bloom>> {
        let mut verified = self.verified.write();

        if epoch == 0 {
            verified.insert(0, PendingItem::ready(Bloom::zero()));
        }

        if !verified.contains_key(&epoch) {
            let missing = MissingBloom::new(epoch);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        verified
            .entry(epoch)
            .or_insert(PendingItem::pending())
            .clear_error();

        FutureItem::new(epoch, self.verified.clone())
            .map(|res| res.map_err(|e| e.into()))
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        blooms: impl Iterator<Item = BloomWithEpoch>,
    ) -> Result<()> {
        for BloomWithEpoch { epoch, bloom } in blooms {
            trace!("Validating bloom {:?} with epoch {}", bloom, epoch);

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => self.validate_and_store(epoch, bloom)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(&self, epoch: u64, bloom: Bloom) -> Result<()> {
        // validate bloom
        if let Err(e) = self.validate_bloom(epoch, bloom) {
            // forward error to both rpc caller(s) and sync handler
            // so we need to make it clonable
            let e = ClonableError::from(e);

            self.verified
                .write()
                .entry(epoch)
                .or_insert(PendingItem::pending())
                .set_error(e.clone());

            bail!(e);
        }

        // store bloom by epoch
        self.verified
            .write()
            .entry(epoch)
            .or_insert(PendingItem::pending())
            .set(bloom);

        self.sync_manager.remove_in_flight(&epoch);
        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *BLOOM_REQUEST_TIMEOUT;
        let blooms = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout blooms ({}): {:?}", blooms.len(), blooms);
        self.sync_manager.insert_waiting(blooms.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>> {
        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        trace!(
            "send_request GetBlooms peer={:?} id={:?} epochs={:?}",
            peer,
            request_id,
            epochs
        );

        let msg: Box<dyn Message> = Box::new(GetBlooms { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_BLOOMS_IN_FLIGHT,
            BLOOM_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    fn validate_bloom(&self, epoch: u64, bloom: Bloom) -> Result<()> {
        // calculate received bloom hash
        let received = keccak(bloom);

        // retrieve local bloom hash
        let expected = self.witnesses.root_hashes_of(epoch)?.logs_bloom_hash;

        // check
        if received != expected {
            bail!(Error::InvalidBloom {
                epoch,
                expected,
                received,
            });
        }

        Ok(())
    }
}
