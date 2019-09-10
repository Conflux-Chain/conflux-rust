// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use futures::Future;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    light_protocol::{
        common::{Peers, UniqueId},
        handler::FullPeerState,
        message::{GetStateEntries, StateEntryWithKey, StateKey},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        MAX_STATE_ENTRIES_IN_FLIGHT, STATE_ENTRY_REQUEST_BATCH_SIZE,
        STATE_ENTRY_REQUEST_TIMEOUT_MS,
    },
    storage::StateProof,
};

use super::{
    future_item::FutureItem, missing_item::TimeOrdered,
    state_roots::StateRoots, sync_manager::SyncManager,
};

pub type StateEntry = Option<Vec<u8>>;

impl Ord for StateKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.epoch.cmp(&other.epoch).then(self.key.cmp(&other.key))
    }
}

impl PartialOrd for StateKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: usize,
    waiting: usize,
}

type MissingStateEntry = TimeOrdered<StateKey>;

pub struct StateEntries {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // state_root sync manager
    state_roots: Arc<StateRoots>,

    // sync and request manager
    sync_manager: SyncManager<StateKey, MissingStateEntry>,

    // state entries received from full node
    verified: Arc<RwLock<HashMap<StateKey, StateEntry>>>,
}

impl StateEntries {
    pub(super) fn new(
        peers: Arc<Peers<FullPeerState>>, state_roots: Arc<StateRoots>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let sync_manager = SyncManager::new(peers.clone());
        let verified = Arc::new(RwLock::new(HashMap::new()));

        StateEntries {
            request_id_allocator,
            sync_manager,
            verified,
            state_roots,
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
    pub fn request_now(
        &self, io: &dyn NetworkContext, epoch: u64, key: Vec<u8>,
    ) -> impl Future<Item = StateEntry, Error = Error> {
        let key = StateKey { epoch, key };

        if !self.verified.read().contains_key(&key) {
            let missing = std::iter::once(MissingStateEntry::new(key.clone()));

            self.sync_manager.request_now(missing, |peer, keys| {
                self.send_request(io, peer, keys)
            });
        }

        FutureItem::new(key, self.verified.clone())
    }

    #[inline]
    pub(super) fn receive(
        &self, entries: impl Iterator<Item = StateEntryWithKey>,
    ) -> Result<(), Error> {
        for StateEntryWithKey { key, entry, proof } in entries {
            info!("Validating state entry {:?} with key {:?}", entry, key);
            self.validate_state_entry(key.epoch, &key.key, &entry, proof)?;

            self.verified.write().insert(key.clone(), entry);
            self.sync_manager.remove_in_flight(&key);
        }

        Ok(())
    }

    #[inline]
    pub(super) fn clean_up(&self) {
        let timeout = Duration::from_millis(STATE_ENTRY_REQUEST_TIMEOUT_MS);
        let entries = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(entries.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, keys: Vec<StateKey>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} keys={:?}", peer, keys);

        if keys.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetStateEntries {
            request_id: self.request_id_allocator.next(),
            keys,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub(super) fn sync(&self, io: &dyn NetworkContext) {
        info!("state entry sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_STATE_ENTRIES_IN_FLIGHT,
            STATE_ENTRY_REQUEST_BATCH_SIZE,
            |peer, keys| self.send_request(io, peer, keys),
        );
    }

    #[inline]
    fn validate_state_entry(
        &self, epoch: u64, key: &Vec<u8>, value: &Option<Vec<u8>>,
        proof: StateProof,
    ) -> Result<(), Error>
    {
        // retrieve local state root
        let root = match self.state_roots.state_root_of(epoch) {
            Some(root) => root.clone(),
            None => {
                warn!(
                    "State root not found, epoch={}, key={:?}, value={:?}, proof={:?}",
                    epoch, key, value, proof
                );
                return Err(ErrorKind::InternalError.into());
            }
        };

        // validate proof
        if !proof.is_valid_kv(key, value.as_ref().map(|v| &**v), root) {
            info!("Invalid proof");
            return Err(ErrorKind::InvalidStateProof.into());
        }

        Ok(())
    }
}
