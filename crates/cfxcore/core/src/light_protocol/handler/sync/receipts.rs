// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    common::{FutureItem, KeyOrdered, PendingItem, SyncManager},
    witnesses::Witnesses,
};
use crate::{
    light_protocol::{
        common::{FullPeerState, Peers},
        error::*,
        message::{msgid, GetReceipts, ReceiptsWithEpoch},
    },
    message::{Message, RequestId},
    verification::compute_receipts_root,
    UniqueId,
};
use cfx_parameters::light::{
    CACHE_TIMEOUT, MAX_RECEIPTS_IN_FLIGHT, RECEIPT_REQUEST_BATCH_SIZE,
    RECEIPT_REQUEST_TIMEOUT,
};
use futures::future::FutureExt;
use lru_time_cache::LruCache;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::BlockReceipts;
use std::{future::Future, sync::Arc};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize higher epochs
type MissingReceipts = KeyOrdered<u64>;

type PendingReceipts = PendingItem<Vec<BlockReceipts>, ClonableError>;

pub struct Receipts {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingReceipts>,

    // epoch receipts received from full node
    verified: Arc<RwLock<LruCache<u64, PendingReceipts>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl Receipts {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        witnesses: Arc<Witnesses>,
    ) -> Self {
        let sync_manager = SyncManager::new(peers.clone(), msgid::GET_RECEIPTS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        Receipts {
            request_id_allocator,
            sync_manager,
            verified,
            witnesses,
        }
    }

    #[inline]
    pub fn print_stats(&self) {
        debug!(
            "receipt sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    #[inline]
    pub fn request(
        &self, epoch: u64,
    ) -> impl Future<Output = Result<Vec<BlockReceipts>>> {
        let mut verified = self.verified.write();

        if epoch == 0 {
            verified.insert(0, PendingItem::ready(vec![]));
        }

        if !verified.contains_key(&epoch) {
            let missing = MissingReceipts::new(epoch);
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
        receipts: impl Iterator<Item = ReceiptsWithEpoch>,
    ) -> Result<()> {
        for ReceiptsWithEpoch {
            epoch,
            epoch_receipts,
        } in receipts
        {
            trace!(
                "Validating receipts {:?} with epoch {}",
                epoch_receipts,
                epoch
            );

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => self.validate_and_store(epoch, epoch_receipts)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, epoch: u64, receipts: Vec<BlockReceipts>,
    ) -> Result<()> {
        // validate receipts
        if let Err(e) = self.validate_receipts(epoch, &receipts) {
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

        // store receipts by epoch
        self.verified
            .write()
            .entry(epoch)
            .or_insert(PendingItem::pending())
            .set(receipts);

        self.sync_manager.remove_in_flight(&epoch);
        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *RECEIPT_REQUEST_TIMEOUT;
        let receipts = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout receipts ({}): {:?}", receipts.len(), receipts);
        self.sync_manager.insert_waiting(receipts.into_iter());

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
            "send_request GetReceipts peer={:?} id={:?} epochs={:?}",
            peer,
            request_id,
            epochs
        );

        let msg: Box<dyn Message> =
            Box::new(GetReceipts { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_RECEIPTS_IN_FLIGHT,
            RECEIPT_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    fn validate_receipts(
        &self, epoch: u64, receipts: &Vec<BlockReceipts>,
    ) -> Result<()> {
        // calculate received receipts root
        // convert Vec<Vec<Receipt>> -> Vec<Arc<Vec<Receipt>>>
        // for API compatibility
        let rs = receipts
            .clone()
            .into_iter()
            .map(|rs| Arc::new(rs))
            .collect();

        let received = compute_receipts_root(&rs);

        // retrieve local receipts root
        let expected = self.witnesses.root_hashes_of(epoch)?.receipts_root_hash;

        // check
        if received != expected {
            bail!(Error::InvalidReceipts {
                epoch,
                expected,
                received,
            });
        }

        Ok(())
    }
}
