// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use cfx_types::Bloom;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{future::Future, sync::Arc};

use crate::{
    hash::keccak,
    light_protocol::{
        common::{FullPeerState, Peers, UniqueId},
        message::{msgid, BloomWithEpoch, GetBlooms},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{
        BLOOM_REQUEST_BATCH_SIZE, BLOOM_REQUEST_TIMEOUT, CACHE_TIMEOUT,
        MAX_BLOOMS_IN_FLIGHT,
    },
};

use super::{
    common::{FutureItem, KeyOrdered, PendingItem, SyncManager},
    witnesses::Witnesses,
};

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize higher epochs
type MissingBloom = KeyOrdered<u64>;

pub struct Blooms {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingBloom>,

    // bloom filters received from full node
    verified: Arc<RwLock<LruCache<u64, PendingItem<Bloom>>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl Blooms {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        witnesses: Arc<Witnesses>,
    ) -> Self
    {
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
    fn get_statistics(&self) -> Statistics {
        Statistics {
            cached: self.verified.read().len(),
            in_flight: self.sync_manager.num_in_flight(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    #[inline]
    pub fn request(&self, epoch: u64) -> impl Future<Output = Bloom> {
        if epoch == 0 {
            self.verified
                .write()
                .insert(0, PendingItem::ready(Bloom::zero()));
        }

        if !self.verified.read().contains_key(&epoch) {
            let missing = MissingBloom::new(epoch);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        FutureItem::new(epoch, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, peer: PeerId, id: RequestId,
        blooms: impl Iterator<Item = BloomWithEpoch>,
    ) -> Result<(), Error>
    {
        for BloomWithEpoch { epoch, bloom } in blooms {
            info!("Validating bloom {:?} with epoch {}", bloom, epoch);

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => self.validate_and_store(epoch, bloom)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, epoch: u64, bloom: Bloom,
    ) -> Result<(), Error> {
        // validate bloom
        self.validate_bloom(epoch, bloom)?;

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
        self.sync_manager.insert_waiting(blooms.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        info!("send_request peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> = Box::new(GetBlooms { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("bloom sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_BLOOMS_IN_FLIGHT,
            BLOOM_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    fn validate_bloom(&self, epoch: u64, bloom: Bloom) -> Result<(), Error> {
        // calculate received bloom hash
        let received = keccak(bloom);

        // retrieve local bloom hash
        let local = match self.witnesses.root_hashes_of(epoch) {
            Some((_, _, bloom_hash)) => bloom_hash,
            None => {
                warn!(
                    "Bloom hash not found, epoch={}, bloom={:?}",
                    epoch, bloom
                );
                return Err(ErrorKind::InternalError.into());
            }
        };

        // check
        if received != local {
            warn!(
                "Bloom validation failed, received={:?}, local={:?}",
                received, local
            );
            return Err(ErrorKind::InvalidBloom.into());
        }

        Ok(())
    }
}
