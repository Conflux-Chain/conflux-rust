// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use lru_time_cache::LruCache;
use parking_lot::RwLock;
use std::{future::Future, sync::Arc};

use crate::{
    light_protocol::{
        common::{FullPeerState, Peers},
        message::{msgid, GetStateEntries, StateEntryWithKey, StateKey},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{
        CACHE_TIMEOUT, MAX_STATE_ENTRIES_IN_FLIGHT,
        STATE_ENTRY_REQUEST_BATCH_SIZE, STATE_ENTRY_REQUEST_TIMEOUT,
    },
    storage::StateProof,
    UniqueId,
};

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    state_roots::StateRoots,
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
    cached: usize,
    in_flight: usize,
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
    verified: Arc<RwLock<LruCache<StateKey, PendingItem<StateEntry>>>>,
}

impl StateEntries {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, state_roots: Arc<StateRoots>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_STATE_ENTRIES);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

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
            cached: self.verified.read().len(),
            in_flight: self.sync_manager.num_in_flight(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    #[inline]
    pub fn request_now(
        &self, io: &dyn NetworkContext, epoch: u64, key: Vec<u8>,
    ) -> impl Future<Output = StateEntry> {
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
    pub fn receive(
        &self, peer: PeerId, id: RequestId,
        entries: impl Iterator<Item = StateEntryWithKey>,
    ) -> Result<(), Error>
    {
        for StateEntryWithKey { key, entry, proof } in entries {
            info!("Validating state entry {:?} with key {:?}", entry, key);

            match self.sync_manager.check_if_requested(peer, id, &key)? {
                None => continue,
                Some(_) => self.validate_and_store(key, entry, proof)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, key: StateKey, entry: Option<Vec<u8>>, proof: StateProof,
    ) -> Result<(), Error> {
        // validate state entry
        self.validate_state_entry(key.epoch, &key.key, &entry, proof)?;

        // store state entry by state key
        self.verified
            .write()
            .entry(key.clone())
            .or_insert(PendingItem::pending())
            .set(entry);

        self.sync_manager.remove_in_flight(&key);

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *STATE_ENTRY_REQUEST_TIMEOUT;
        let entries = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(entries.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, keys: Vec<StateKey>,
    ) -> Result<Option<RequestId>, Error> {
        info!("send_request peer={:?} keys={:?}", peer, keys);

        if keys.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> =
            Box::new(GetStateEntries { request_id, keys });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
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
