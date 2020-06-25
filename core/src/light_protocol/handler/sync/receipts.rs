// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use cfx_types::H256;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{future::Future, sync::Arc};

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        message::{msgid, GetReceipts, ReceiptsWithEpoch},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{
            CACHE_TIMEOUT, MAX_RECEIPTS_IN_FLIGHT, RECEIPT_REQUEST_BATCH_SIZE,
            RECEIPT_REQUEST_TIMEOUT,
        },
    },
    primitives::BlockReceipts,
    UniqueId,
};

use super::common::{
    FutureItem, KeyOrdered, LedgerProof, PendingItem, SyncManager,
};
use crate::verification::compute_receipts_root;
use network::node_table::NodeId;

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize higher epochs
type MissingReceipts = KeyOrdered<u64>;

pub struct Receipts {
    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingReceipts>,

    // epoch receipts received from full node
    verified: Arc<RwLock<LruCache<u64, PendingItem<Vec<BlockReceipts>>>>>,
}

impl Receipts {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager = SyncManager::new(peers.clone(), msgid::GET_RECEIPTS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        Receipts {
            ledger,
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
    pub fn request(
        &self, epoch: u64,
    ) -> impl Future<Output = Vec<BlockReceipts>> {
        if epoch == 0 {
            self.verified.write().insert(0, PendingItem::ready(vec![]));
        }

        if !self.verified.read().contains_key(&epoch) {
            let missing = MissingReceipts::new(epoch);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        FutureItem::new(epoch, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        receipts: impl Iterator<Item = ReceiptsWithEpoch>,
    ) -> Result<(), Error>
    {
        for ReceiptsWithEpoch {
            epoch,
            epoch_receipts,
            witness,
        } in receipts
        {
            debug!(
                "Validating receipts {:?} with epoch {}",
                epoch_receipts, epoch
            );

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => {
                    self.validate_and_store(epoch, epoch_receipts, witness)?
                }
            };
        }

        Ok(())
    }

    #[inline]
    fn validate_and_store(
        &self, epoch: u64, receipts: Vec<BlockReceipts>, witness: Vec<H256>,
    ) -> Result<(), Error> {
        // validate receipts
        self.validate_receipts(epoch, &receipts, witness)?;

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
        let receiptss = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(receiptss.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        debug!("send_request peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> =
            Box::new(GetReceipts { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        debug!("receipt sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_RECEIPTS_IN_FLIGHT,
            RECEIPT_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    pub fn validate_receipts(
        &self, epoch: u64, receipts: &Vec<BlockReceipts>,
        mut witness: Vec<H256>,
    ) -> Result<(), Error>
    {
        // height of header that can be used to validate `epoch`
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;

        // get witness info from local ledger
        let w = match self.ledger.witness_of_header_at(height) {
            Some(w) => w,
            None => {
                warn!("Unable to verify header using local ledger");
                return Err(ErrorKind::NoWitnessForHeight(height).into());
            }
        };

        // validate witness info
        let header = self.ledger.pivot_header_of(w)?;

        if w == height && witness.len() == 0 {
            witness = vec![*header.deferred_receipts_root()];
        }

        LedgerProof::ReceiptsRoot(&witness).validate(&header)?;

        // take correct receipts_root_hash from validated response hashes
        assert!(w >= height);
        let index = (w - height) as usize;
        assert!(index < witness.len());
        let correct = witness[index];

        // validate `state_root`
        // calculate received receipts root
        // convert Vec<Vec<Receipt>> -> Vec<Arc<Vec<Receipt>>>
        // for API compatibility
        let rs = receipts
            .clone()
            .into_iter()
            .map(|rs| Arc::new(rs))
            .collect();

        let received = compute_receipts_root(&rs);

        if received != correct {
            warn!(
                "Receipts validation failed, received={:?}, correct={:?}",
                received, correct
            );
            return Err(ErrorKind::InvalidReceipts.into());
        }

        Ok(())
    }
}
