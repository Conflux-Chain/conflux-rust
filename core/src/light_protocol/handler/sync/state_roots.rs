// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use futures::Future;
use parking_lot::RwLock;
use primitives::StateRoot;
use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    light_protocol::{
        common::{Peers, UniqueId},
        handler::FullPeerState,
        message::{GetStateRoots, StateRootWithEpoch},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        MAX_STATE_ROOTS_IN_FLIGHT, STATE_ROOT_REQUEST_BATCH_SIZE,
        STATE_ROOT_REQUEST_TIMEOUT_MS,
    },
};

use super::{
    future_item::FutureItem, missing_item::TimeOrdered,
    sync_manager::SyncManager, witnesses::Witnesses,
};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: usize,
    waiting: usize,
}

type MissingStateRoot = TimeOrdered<u64>;

pub struct StateRoots {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingStateRoot>,

    // bloom filters received from full node
    verified: Arc<RwLock<HashMap<u64, StateRoot>>>,

    // witness sync manager
    witnesses: Arc<Witnesses>,
}

impl StateRoots {
    pub(super) fn new(
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        witnesses: Arc<Witnesses>,
    ) -> Self
    {
        let sync_manager = SyncManager::new(peers.clone());
        let verified = Arc::new(RwLock::new(HashMap::new()));

        StateRoots {
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

    /// Get state root for `epoch` from local cache.
    #[inline]
    pub fn state_root_of(&self, epoch: u64) -> Option<StateRoot> {
        self.verified.read().get(&epoch).cloned()
    }

    #[inline]
    pub fn request_now(
        &self, io: &dyn NetworkContext, epoch: u64,
    ) -> impl Future<Item = StateRoot, Error = Error> {
        if !self.verified.read().contains_key(&epoch) {
            let missing = std::iter::once(MissingStateRoot::new(epoch));

            self.sync_manager.request_now(missing, |peer, epochs| {
                self.send_request(io, peer, epochs)
            });
        }

        FutureItem::new(epoch, self.verified.clone())
    }

    #[inline]
    pub(super) fn receive(
        &self, state_roots: impl Iterator<Item = StateRootWithEpoch>,
    ) -> Result<(), Error> {
        for StateRootWithEpoch { epoch, state_root } in state_roots {
            info!(
                "Validating state root {:?} with epoch {}",
                state_root, epoch
            );
            self.validate_state_root(epoch, &state_root)?;

            self.verified.write().insert(epoch, state_root);
            self.sync_manager.remove_in_flight(&epoch);
        }

        Ok(())
    }

    #[inline]
    pub(super) fn clean_up(&self) {
        let timeout = Duration::from_millis(STATE_ROOT_REQUEST_TIMEOUT_MS);
        let state_roots = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(state_roots.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, epochs: Vec<u64>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetStateRoots {
            request_id: self.request_id_allocator.next(),
            epochs,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub(super) fn sync(&self, io: &dyn NetworkContext) {
        info!("state root sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_STATE_ROOTS_IN_FLIGHT,
            STATE_ROOT_REQUEST_BATCH_SIZE,
            |peer, epochs| self.send_request(io, peer, epochs),
        );
    }

    #[inline]
    fn validate_state_root(
        &self, epoch: u64, state_root: &StateRoot,
    ) -> Result<(), Error> {
        // calculate received state root hash
        let received = state_root.compute_state_root_hash();

        // retrieve local state root hash
        let local = match self.witnesses.root_hashes_of(epoch) {
            Some((state_root, _, _)) => state_root,
            None => {
                warn!(
                    "State root hash not found, epoch={}, state_root={:?}",
                    epoch, state_root
                );
                return Err(ErrorKind::InternalError.into());
            }
        };

        // check
        if received != local {
            warn!(
                "State root validation failed, received={:?}, local={:?}",
                received, local
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        Ok(())
    }
}
