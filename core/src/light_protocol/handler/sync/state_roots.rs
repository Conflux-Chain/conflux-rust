// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use cfx_types::H256;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use primitives::StateRoot;
use std::{future::Future, sync::Arc};

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        message::{msgid, GetStateRoots, StateRootWithEpoch},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{
            CACHE_TIMEOUT, MAX_STATE_ROOTS_IN_FLIGHT,
            STATE_ROOT_REQUEST_BATCH_SIZE, STATE_ROOT_REQUEST_TIMEOUT,
        },
    },
    UniqueId,
};

use super::common::{
    FutureItem, LedgerProof, PendingItem, SyncManager, TimeOrdered,
};
use network::node_table::NodeId;

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

type MissingStateRoot = TimeOrdered<u64>;

pub struct StateRoots {
    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingStateRoot>,

    // bloom filters received from full node
    verified: Arc<RwLock<LruCache<u64, PendingItem<StateRoot>>>>,
}

impl StateRoots {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_STATE_ROOTS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        StateRoots {
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

    /// Get state root for `epoch` from local cache.
    #[inline]
    pub fn state_root_of(&self, epoch: u64) -> Option<StateRoot> {
        match self.verified.write().get(&epoch) {
            Some(PendingItem::Ready(i)) => Some(i.clone()),
            _ => None,
        }
    }

    #[inline]
    pub fn request_now(
        &self, io: &dyn NetworkContext, epoch: u64,
    ) -> impl Future<Output = StateRoot> {
        if !self.verified.read().contains_key(&epoch) {
            let missing = std::iter::once(MissingStateRoot::new(epoch));

            self.sync_manager.request_now(missing, |peer, epochs| {
                self.send_request(io, peer, epochs)
            });
        }

        FutureItem::new(epoch, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        state_roots: impl Iterator<Item = StateRootWithEpoch>,
    ) -> Result<(), Error>
    {
        for StateRootWithEpoch {
            epoch,
            state_root,
            witness,
        } in state_roots
        {
            debug!(
                "Validating state root {:?} with epoch {}",
                state_root, epoch
            );

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => {
                    self.validate_and_store(epoch, state_root, witness)?
                }
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, epoch: u64, state_root: StateRoot, witness: Vec<H256>,
    ) -> Result<(), Error> {
        // validate state root
        self.validate_state_root(epoch, &state_root, witness)?;

        // store state root by epoch
        self.verified
            .write()
            .entry(epoch)
            .or_insert(PendingItem::pending())
            .set(state_root);

        self.sync_manager.remove_in_flight(&epoch);
        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *STATE_ROOT_REQUEST_TIMEOUT;
        let state_roots = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(state_roots.into_iter());

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
            Box::new(GetStateRoots { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        debug!("state root sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_STATE_ROOTS_IN_FLIGHT,
            STATE_ROOT_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    pub fn validate_state_root(
        &self, epoch: u64, state_root: &StateRoot, witness: Vec<H256>,
    ) -> Result<(), Error> {
        let state_root_hash = state_root.compute_state_root_hash();
        self.validate_state_root_hash(epoch, state_root_hash, witness)
    }

    #[inline]
    pub fn validate_state_root_hash(
        &self, epoch: u64, state_root_hash: H256, mut witness: Vec<H256>,
    ) -> Result<(), Error> {
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
            witness = vec![*header.deferred_state_root()];
        }

        LedgerProof::StateRoot(&witness).validate(&header)?;

        // take correct state_root_hash from validated response hashes
        assert!(w >= height);
        let index = (w - height) as usize;
        assert!(index < witness.len());
        let correct = witness[index];

        // validate `state_root`
        let received = state_root_hash;

        if received != correct {
            warn!(
                "State root validation failed, received={:?}, correct={:?}",
                received, correct
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        Ok(())
    }
}
