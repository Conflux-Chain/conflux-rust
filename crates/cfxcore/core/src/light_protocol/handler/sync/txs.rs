// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::common::{FutureItem, PendingItem, SyncManager, TimeOrdered};
use crate::{
    light_protocol::{
        common::{FullPeerState, Peers},
        error::*,
        message::{msgid, GetTxs},
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::light::{
    CACHE_TIMEOUT, MAX_TXS_IN_FLIGHT, TX_REQUEST_BATCH_SIZE, TX_REQUEST_TIMEOUT,
};
use cfx_types::H256;
use futures::future::FutureExt;
use lru_time_cache::LruCache;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::SignedTransaction;
use std::{future::Future, sync::Arc};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingTx = TimeOrdered<H256>;

type PendingTx = PendingItem<SignedTransaction, ClonableError>;

pub struct Txs {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingTx>,

    // txs received from full node
    verified: Arc<RwLock<LruCache<H256, PendingTx>>>,
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
    pub fn print_stats(&self) {
        debug!(
            "tx sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    #[inline]
    pub fn request_now(
        &self, io: &dyn NetworkContext, hash: H256,
    ) -> impl Future<Output = Result<SignedTransaction>> {
        let mut verified = self.verified.write();

        if !verified.contains_key(&hash) {
            let missing = std::iter::once(MissingTx::new(hash));

            self.sync_manager.request_now(missing, |peer, hashes| {
                self.send_request(io, peer, hashes)
            });
        }

        verified
            .entry(hash)
            .or_insert(PendingItem::pending())
            .clear_error();

        FutureItem::new(hash, self.verified.clone())
            .map(|res| res.map_err(|e| e.into()))
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        txs: impl Iterator<Item = SignedTransaction>,
    ) -> Result<()> {
        for tx in txs {
            let hash = tx.hash();
            trace!("Validating tx {:?}", hash);

            match self.sync_manager.check_if_requested(peer, id, &hash)? {
                None => continue,
                Some(_) => self.validate_and_store(tx)?,
            };
        }

        Ok(())
    }

    #[inline]
    fn validate_and_store(&self, tx: SignedTransaction) -> Result<()> {
        let hash = tx.hash();

        // validate tx
        if let Err(e) = self.validate_tx(&tx) {
            // forward error to both rpc caller(s) and sync handler
            // so we need to make it clonable
            let e = ClonableError::from(e);

            self.verified
                .write()
                .entry(hash)
                .or_insert(PendingItem::pending())
                .set_error(e.clone());

            bail!(e);
        }

        self.verified
            .write()
            .entry(hash)
            .or_insert(PendingItem::pending())
            .set(tx);

        self.sync_manager.remove_in_flight(&hash);
        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *TX_REQUEST_TIMEOUT;
        let txs = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout txs ({}): {:?}", txs.len(), txs);
        self.sync_manager.insert_waiting(txs.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, hashes: Vec<H256>,
    ) -> Result<Option<RequestId>> {
        if hashes.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        trace!(
            "send_request GetTxs peer={:?} id={:?} hashes={:?}",
            peer,
            request_id,
            hashes
        );

        let msg: Box<dyn Message> = Box::new(GetTxs { request_id, hashes });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_TXS_IN_FLIGHT,
            TX_REQUEST_BATCH_SIZE,
            |peer, tx_hashes| self.send_request(io, peer, tx_hashes),
        );
    }

    #[inline]
    pub fn validate_tx(&self, tx: &SignedTransaction) -> Result<()> {
        match tx.verify_public(false /* skip */) {
            Ok(true) => {}
            _ => {
                warn!("Tx signature verification failed for {:?}", tx);
                bail!(Error::InvalidTxSignature { hash: tx.hash() });
            }
        }

        Ok(())
    }
}
