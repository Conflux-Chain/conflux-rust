// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    witnesses::Witnesses,
};
use crate::{
    light_protocol::{
        common::{FullPeerState, Peers},
        error::*,
        message::{msgid, GetStateRoots, StateRootWithEpoch},
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::light::{
    CACHE_TIMEOUT, MAX_STATE_ROOTS_IN_FLIGHT, STATE_ROOT_REQUEST_BATCH_SIZE,
    STATE_ROOT_REQUEST_TIMEOUT,
};
use futures::future::FutureExt;
use lru_time_cache::LruCache;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::StateRoot;
use std::{future::Future, sync::Arc};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

type MissingStateRoot = TimeOrdered<u64>;

type PendingStateRoot = PendingItem<StateRoot, ClonableError>;

pub struct StateRoots {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // number of epochs per snapshot period
    snapshot_epoch_count: u64,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingStateRoot>,

    // bloom filters received from full node
    verified: Arc<RwLock<LruCache<u64, PendingStateRoot>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl StateRoots {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        snapshot_epoch_count: u64, witnesses: Arc<Witnesses>,
    ) -> Self {
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_STATE_ROOTS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        StateRoots {
            request_id_allocator,
            sync_manager,
            snapshot_epoch_count,
            verified,
            witnesses,
        }
    }

    #[inline]
    pub fn print_stats(&self) {
        debug!(
            "state root sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
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
    ) -> impl Future<Output = Result<StateRoot>> {
        let mut verified = self.verified.write();

        if !verified.contains_key(&epoch) {
            let missing = std::iter::once(MissingStateRoot::new(epoch));

            self.sync_manager.request_now(missing, |peer, epochs| {
                self.send_request(io, peer, epochs)
            });
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
        state_roots: impl Iterator<Item = StateRootWithEpoch>,
    ) -> Result<()> {
        for StateRootWithEpoch { epoch, state_root } in state_roots {
            trace!(
                "Validating state root {:?} with epoch {}",
                state_root,
                epoch
            );

            match self.sync_manager.check_if_requested(peer, id, &epoch)? {
                None => continue,
                Some(_) => self.validate_and_store(epoch, state_root)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, epoch: u64, state_root: StateRoot,
    ) -> Result<()> {
        // validate state root
        if let Err(e) = self.validate_state_root(epoch, &state_root) {
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
        let roots = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout state-roots ({}): {:?}", roots.len(), roots);
        self.sync_manager.insert_waiting(roots.into_iter());

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
            "send_request GetStateRoots peer={:?} id={:?} epochs={:?}",
            peer,
            request_id,
            epochs
        );

        let msg: Box<dyn Message> =
            Box::new(GetStateRoots { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_STATE_ROOTS_IN_FLIGHT,
            STATE_ROOT_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    pub fn validate_state_root(
        &self, epoch: u64, state_root: &StateRoot,
    ) -> Result<()> {
        // calculate received state root hash
        let received = state_root.compute_state_root_hash();

        // retrieve local state root hash
        let expected = self.witnesses.root_hashes_of(epoch)?.state_root_hash;

        // check
        if received != expected {
            bail!(Error::InvalidStateRoot {
                epoch,
                expected,
                received,
            });
        }

        Ok(())
    }

    #[inline]
    pub fn validate_prev_snapshot_state_root(
        &self, current_epoch: u64,
        maybe_prev_snapshot_state_root: &Option<StateRoot>,
    ) -> Result<()> {
        let snapshot_epoch_count = self.snapshot_epoch_count;

        match maybe_prev_snapshot_state_root {
            Some(ref root) => {
                // root provided for non-existent epoch
                if current_epoch <= snapshot_epoch_count {
                    // previous root should not have been provided
                    // for the first snapshot period
                    bail!(Error::InvalidPreviousStateRoot {
                        current_epoch,
                        snapshot_epoch_count,
                        root: maybe_prev_snapshot_state_root.clone()
                    });
                }

                // root provided for previous snapshot
                self.validate_state_root(
                    current_epoch - snapshot_epoch_count,
                    &root,
                )?;
            }
            None => {
                if current_epoch > snapshot_epoch_count {
                    // previous root should have been provided
                    // for subsequent snapshot periods
                    bail!(Error::InvalidPreviousStateRoot {
                        current_epoch,
                        snapshot_epoch_count,
                        root: maybe_prev_snapshot_state_root.clone()
                    });
                }
            }
        }

        Ok(())
    }
}
