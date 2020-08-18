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
        error::*,
        message::{
            msgid, GetStateEntries, StateEntryProof, StateEntryWithKey,
            StateKey,
        },
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::light::{
        CACHE_TIMEOUT, MAX_STATE_ENTRIES_IN_FLIGHT,
        STATE_ENTRY_REQUEST_BATCH_SIZE, STATE_ENTRY_REQUEST_TIMEOUT,
    },
    UniqueId,
};

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    state_roots::StateRoots,
};
use futures::future::FutureExt;
use network::node_table::NodeId;
use primitives::StorageKey;

pub type StateEntry = Option<Vec<u8>>;

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

type MissingStateEntry = TimeOrdered<StateKey>;

type PendingStateEntry = PendingItem<StateEntry, ClonableError>;

pub struct StateEntries {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // state_root sync manager
    state_roots: Arc<StateRoots>,

    // sync and request manager
    sync_manager: SyncManager<StateKey, MissingStateEntry>,

    // state entries received from full node
    verified: Arc<RwLock<LruCache<StateKey, PendingStateEntry>>>,
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
    ) -> impl Future<Output = Result<StateEntry>> {
        let mut verified = self.verified.write();
        let key = StateKey { epoch, key };

        if !verified.contains_key(&key) {
            let missing = std::iter::once(MissingStateEntry::new(key.clone()));

            self.sync_manager.request_now(missing, |peer, keys| {
                self.send_request(io, peer, keys)
            });
        }

        verified
            .entry(key.clone())
            .or_insert(PendingItem::pending())
            .clear_error();

        FutureItem::new(key, self.verified.clone())
            .map(|res| res.map_err(|e| e.into()))
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        entries: impl Iterator<Item = StateEntryWithKey>,
    ) -> Result<()>
    {
        for StateEntryWithKey { key, entry, proof } in entries {
            debug!(
                "Validating state entry {:?} with key {:?} and proof {:?}",
                entry, key, proof
            );

            match self.sync_manager.check_if_requested(peer, id, &key)? {
                None => continue,
                Some(_) => self.validate_and_store(key, entry, proof)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, key: StateKey, entry: Option<Vec<u8>>, proof: StateEntryProof,
    ) -> Result<()> {
        // validate state entry
        if let Err(e) =
            self.validate_state_entry(key.epoch, &key.key, &entry, proof)
        {
            // forward error to both rpc caller(s) and sync handler
            // so we need to make it clonable
            let e = ClonableError::from(e);

            self.verified
                .write()
                .entry(key.clone())
                .or_insert(PendingItem::pending())
                .set_error(e.clone());

            bail!(e);
        }

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
        &self, io: &dyn NetworkContext, peer: &NodeId, keys: Vec<StateKey>,
    ) -> Result<Option<RequestId>> {
        debug!("send_request peer={:?} keys={:?}", peer, keys);

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
        debug!("state entry sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_STATE_ENTRIES_IN_FLIGHT,
            STATE_ENTRY_REQUEST_BATCH_SIZE,
            |peer, keys| self.send_request(io, peer, keys),
        );
    }

    #[inline]
    fn validate_state_entry(
        &self, epoch: u64, key: &Vec<u8>, value: &Option<Vec<u8>>,
        proof: StateEntryProof,
    ) -> Result<()>
    {
        // validate state root
        let state_root = proof.state_root;

        self.state_roots
            .validate_state_root(epoch, &state_root)
            .chain_err(|| ErrorKind::InvalidStateProof {
                epoch,
                key: key.clone(),
                value: value.clone(),
                reason: "Validation of current state root failed",
            })?;

        // validate previous state root
        let maybe_prev_root = proof.prev_snapshot_state_root;

        self.state_roots
            .validate_prev_snapshot_state_root(epoch, &maybe_prev_root)
            .chain_err(|| ErrorKind::InvalidStateProof {
                epoch,
                key: key.clone(),
                value: value.clone(),
                reason: "Validation of previous state root failed",
            })?;

        // construct padding
        let maybe_intermediate_padding = maybe_prev_root.map(|root| {
            StorageKey::delta_mpt_padding(
                &root.snapshot_root,
                &root.intermediate_delta_root,
            )
        });

        // validate state entry
        if !proof.state_proof.is_valid_kv(
            key,
            value.as_ref().map(|v| &**v),
            state_root,
            maybe_intermediate_padding,
        ) {
            bail!(ErrorKind::InvalidStateProof {
                epoch,
                key: key.clone(),
                value: value.clone(),
                reason: "Validation of merkle proof failed",
            });
        }

        Ok(())
    }
}
