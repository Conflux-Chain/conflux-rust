// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;
extern crate lru_time_cache;

use cfx_types::H256;
use futures::Future;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use primitives::SignedTransaction;
use std::sync::Arc;

use crate::{
    light_protocol::{
        common::{FullPeerState, Peers, UniqueId},
        message::{msgid, GetTxs},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        CACHE_TIMEOUT, MAX_TXS_IN_FLIGHT, TX_REQUEST_BATCH_SIZE,
        TX_REQUEST_TIMEOUT,
    },
};

use super::common::{FutureItem, SyncManager, TimeOrdered};

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingTx = TimeOrdered<H256>;

pub struct Txs {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingTx>,

    // txs received from full node
    verified: Arc<RwLock<LruCache<H256, SignedTransaction>>>,
}

impl Txs {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
    ) -> Self {
        let sync_manager = SyncManager::new(peers.clone(), msgid::GET_TXS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        Txs {
            request_id_allocator,
            sync_manager,
            verified,
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
    pub fn request_now(
        &self, io: &dyn NetworkContext, hash: H256,
    ) -> impl Future<Item = SignedTransaction, Error = Error> {
        if !self.verified.read().contains_key(&hash) {
            let missing = std::iter::once(MissingTx::new(hash));

            self.sync_manager.request_now(missing, |peer, hashes| {
                self.send_request(io, peer, hashes)
            });
        }

        FutureItem::new(hash, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, txs: impl Iterator<Item = SignedTransaction>,
    ) -> Result<(), Error> {
        for tx in txs {
            let hash = tx.hash();
            info!("Validating tx {:?}", hash);
            self.validate_tx(&tx)?;

            self.verified.write().insert(hash, tx);
            self.sync_manager.remove_in_flight(&hash);
        }

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *TX_REQUEST_TIMEOUT;
        let txs = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(txs.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetTxs {
            request_id: self.request_id_allocator.next(),
            hashes,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("tx sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_TXS_IN_FLIGHT,
            TX_REQUEST_BATCH_SIZE,
            |peer, tx_hashes| self.send_request(io, peer, tx_hashes),
        );
    }

    #[inline]
    fn validate_tx(&self, tx: &SignedTransaction) -> Result<(), Error> {
        match tx.verify_public(false /* skip */) {
            Ok(true) => {}
            _ => {
                warn!("Tx signature verification failed for {:?}", tx);
                return Err(ErrorKind::InvalidTxSignature.into());
            }
        }

        Ok(())
    }
}
