// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use cfx_types::Bloom;
use futures::Future;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    hash::keccak,
    light_protocol::{
        common::{FullPeerState, Peers, UniqueId},
        message::{BloomWithEpoch, GetBlooms},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        BLOOM_REQUEST_BATCH_SIZE, BLOOM_REQUEST_TIMEOUT_MS,
        MAX_BLOOMS_IN_FLIGHT,
    },
};

use super::{
    common::{FutureItem, KeyOrdered, SyncManager},
    witnesses::Witnesses,
};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: usize,
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
    verified: Arc<RwLock<HashMap<u64, Bloom>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl Blooms {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        witnesses: Arc<Witnesses>,
    ) -> Self
    {
        let sync_manager = SyncManager::new(peers.clone());
        let verified = Arc::new(RwLock::new(HashMap::new()));

        verified.write().insert(0, Bloom::zero());

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
            in_flight: self.sync_manager.num_in_flight(),
            verified: self.verified.read().len(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    #[inline]
    pub fn request(
        &self, epoch: u64,
    ) -> impl Future<Item = Bloom, Error = Error> {
        if !self.verified.read().contains_key(&epoch) {
            let missing = MissingBloom::new(epoch);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        FutureItem::new(epoch, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, blooms: impl Iterator<Item = BloomWithEpoch>,
    ) -> Result<(), Error> {
        for BloomWithEpoch { epoch, bloom } in blooms {
            info!("Validating bloom {:?} with epoch {}", bloom, epoch);
            self.validate_bloom(epoch, bloom)?;

            self.verified.write().insert(epoch, bloom);
            self.sync_manager.remove_in_flight(&epoch);
        }

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = Duration::from_millis(BLOOM_REQUEST_TIMEOUT_MS);
        let blooms = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(blooms.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, epochs: Vec<u64>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetBlooms {
            request_id: self.request_id_allocator.next(),
            epochs,
        });

        msg.send(io, peer)?;
        Ok(())
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
