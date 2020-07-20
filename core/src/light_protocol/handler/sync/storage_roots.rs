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
            msgid, GetStorageRoots, StorageRootKey, StorageRootProof,
            StorageRootWithKey,
        },
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::light::{
        CACHE_TIMEOUT, MAX_STORAGE_ROOTS_IN_FLIGHT,
        STORAGE_ROOT_REQUEST_BATCH_SIZE, STORAGE_ROOT_REQUEST_TIMEOUT,
    },
    UniqueId,
};

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    state_roots::StateRoots,
};
use cfx_types::H160;
use network::node_table::NodeId;
use primitives::{StorageKey, StorageRoot};

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

type MissingStorageRoot = TimeOrdered<StorageRootKey>;

pub struct StorageRoots {
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // number of epochs per snapshot period
    snapshot_epoch_count: u64,

    // state_root sync manager
    state_roots: Arc<StateRoots>,

    // sync and request manager
    sync_manager: SyncManager<StorageRootKey, MissingStorageRoot>,

    // state entries received from full node
    verified:
        Arc<RwLock<LruCache<StorageRootKey, PendingItem<Option<StorageRoot>>>>>,
}

impl StorageRoots {
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, snapshot_epoch_count: u64,
        state_roots: Arc<StateRoots>, request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_STORAGE_ROOTS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        StorageRoots {
            request_id_allocator,
            snapshot_epoch_count,
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
        &self, io: &dyn NetworkContext, epoch: u64, address: H160,
    ) -> impl Future<Output = Option<StorageRoot>> {
        let key = StorageRootKey { epoch, address };

        if !self.verified.read().contains_key(&key) {
            let missing = std::iter::once(MissingStorageRoot::new(key.clone()));

            self.sync_manager.request_now(missing, |peer, keys| {
                self.send_request(io, peer, keys)
            });
        }

        FutureItem::new(key, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        entries: impl Iterator<Item = StorageRootWithKey>,
    ) -> Result<()>
    {
        for StorageRootWithKey { key, root, proof } in entries {
            debug!("Validating storage root {:?} with key {:?}", root, key);

            match self.sync_manager.check_if_requested(peer, id, &key)? {
                None => continue,
                Some(_) => self.validate_and_store(key, root, proof)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, key: StorageRootKey, root: Option<StorageRoot>,
        proof: StorageRootProof,
    ) -> Result<()>
    {
        // validate storage root
        self.validate_storage_root(key.epoch, &key.address, &root, proof)?;

        // store storage root by storage root key
        self.verified
            .write()
            .entry(key.clone())
            .or_insert(PendingItem::pending())
            .set(root);

        self.sync_manager.remove_in_flight(&key);

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *STORAGE_ROOT_REQUEST_TIMEOUT;
        let entries = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(entries.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        keys: Vec<StorageRootKey>,
    ) -> Result<Option<RequestId>>
    {
        debug!("send_request peer={:?} keys={:?}", peer, keys);

        if keys.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> =
            Box::new(GetStorageRoots { request_id, keys });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        debug!("storage root sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_STORAGE_ROOTS_IN_FLIGHT,
            STORAGE_ROOT_REQUEST_BATCH_SIZE,
            |peer, keys| self.send_request(io, peer, keys),
        );
    }

    #[inline]
    fn validate_storage_root(
        &self, epoch: u64, address: &H160, storage_root: &Option<StorageRoot>,
        proof: StorageRootProof,
    ) -> Result<()>
    {
        // validate state root
        let state_root = proof.state_root;
        self.state_roots
            .validate_state_root(epoch, &state_root)
            .chain_err(|| {
                ErrorKind::InvalidStorageRootProof(
                    "Validation of current state root failed",
                )
            })?;

        // validate previous state root
        let maybe_prev_root = proof.prev_snapshot_state_root;

        match maybe_prev_root {
            Some(ref root) => {
                if epoch <= self.snapshot_epoch_count {
                    return Err(ErrorKind::InvalidStorageRootProof(
                        "Validation of previous state root failed",
                    )
                    .into());
                }

                self.state_roots
                    .validate_state_root(
                        epoch - self.snapshot_epoch_count,
                        &root,
                    )
                    .chain_err(|| {
                        ErrorKind::InvalidStorageRootProof(
                            "Validation of previous state root failed",
                        )
                    })?;
            }
            None => {
                if epoch > self.snapshot_epoch_count {
                    return Err(ErrorKind::InvalidStorageRootProof(
                        "Validation of previous state root failed",
                    )
                    .into());
                }
            }
        }

        // construct padding
        let maybe_intermediate_padding = maybe_prev_root.map(|root| {
            StorageKey::delta_mpt_padding(
                &root.snapshot_root,
                &root.intermediate_delta_root,
            )
        });

        // validate proof
        let key = StorageKey::new_storage_root_key(&address).to_key_bytes();

        if !proof.merkle_proof.is_valid(
            &key,
            storage_root,
            state_root,
            maybe_intermediate_padding,
        ) {
            warn!(
                "Invalid storage root proof for {:?} under key {:?}",
                storage_root, key
            );
            return Err(ErrorKind::InvalidStorageRootProof(
                "Validation of merkle proof failed",
            )
            .into());
        }

        Ok(())
    }
}
