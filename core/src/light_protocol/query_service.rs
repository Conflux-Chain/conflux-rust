// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H160;
use primitives::{Account, StateRoot};
use std::sync::Arc;

use crate::{
    consensus::ConsensusGraph,
    network::{NetworkService, PeerId},
    statedb::StorageKey,
    storage,
    sync::SynchronizationGraph,
};

use super::{
    handler::QueryResult,
    message::{GetStateEntry, GetStateRoot},
    Error, ErrorKind, Handler as LightHandler, LIGHT_PROTOCOL_ID,
    LIGHT_PROTOCOL_VERSION,
};

pub struct QueryService {
    handler: Arc<LightHandler>,
    network: Arc<NetworkService>,
}

impl QueryService {
    pub fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
        network: Arc<NetworkService>,
    ) -> Self
    {
        QueryService {
            handler: Arc::new(LightHandler::new(consensus, graph)),
            network,
        }
    }

    pub fn register(&self) -> Result<(), String> {
        self.network
            .register_protocol(
                self.handler.clone(),
                LIGHT_PROTOCOL_ID,
                &[LIGHT_PROTOCOL_VERSION],
            )
            .map_err(|e| {
                format!("failed to register protocol QueryService: {:?}", e)
            })
    }

    pub fn query_state_root(
        &self, peer: PeerId, epoch: u64,
    ) -> Result<StateRoot, Error> {
        // TODO(thegaram): retrieve from cache
        info!("query_state_root epoch={:?}", epoch);

        let req = GetStateRoot {
            request_id: 0,
            epoch,
        };

        self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
            match self.handler.query.execute(io, peer, req)? {
                QueryResult::StateRoot(sr) => Ok(sr),
                _ => Err(ErrorKind::UnexpectedResponse.into()),
            }
        })
    }

    pub fn query_state_entry(
        &self, peer: PeerId, epoch: u64, key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        info!("query_state_entry epoch={:?} key={:?}", epoch, key);

        let req = GetStateEntry {
            request_id: 0,
            epoch,
            key,
        };

        self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
            match self.handler.query.execute(io, peer, req)? {
                QueryResult::StateEntry(entry) => Ok(entry),
                _ => Err(ErrorKind::UnexpectedResponse.into()),
            }
        })
    }

    pub fn query_account(
        &self, peer: PeerId, epoch: u64, address: H160,
    ) -> Result<Option<Account>, Error> {
        info!(
            "query_account peer={:?} epoch={:?} address={:?}",
            peer, epoch, address
        );

        // retrieve state root from peer
        let state_root = self.query_state_root(peer, epoch)?;

        // calculate corresponding state trie key
        let key = {
            let padding = storage::MultiVersionMerklePatriciaTrie::padding(
                &state_root.snapshot_root,
                &state_root.intermediate_delta_root,
            );

            StorageKey::new_account_key(&address, &padding)
                .as_ref()
                .to_vec()
        };

        // retrieve state entry from peer
        let entry = self.query_state_entry(peer, epoch, key)?;

        let account = match entry {
            None => None,
            Some(entry) => Some(rlp::decode(&entry[..])?),
        };

        Ok(account)
    }

    pub fn get_account(&self, epoch: u64, address: H160) -> Option<Account> {
        info!("get_account epoch={:?} address={:?}", epoch, address);

        // try each peer until we succeed
        // TODO(thegaram): only query peers who already have `epoch`
        for peer in self.handler.peers.all_peers_shuffled() {
            match self.query_account(peer, epoch, address) {
                Ok(account) => return account,
                Err(e) => {
                    warn!(
                        "Failed to get account from peer={:?}: {:?}",
                        peer, e
                    );
                }
            };
        }

        None
    }

    /// Relay raw transaction to all peers.
    // TODO(thegaram): consider returning TxStatus instead of bool,
    // e.g. Failed, Sent/Pending, Confirmed, etc.
    pub fn send_raw_tx(&self, raw: Vec<u8>) -> bool {
        debug!("send_raw_tx raw={:?}", raw);

        let mut success = false;

        for peer in self.handler.peers.all_peers_shuffled() {
            // relay to peer
            let res = self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
                self.handler.send_raw_tx(io, peer, raw.clone())
            });

            // check error
            match res {
                Err(e) => warn!("Failed to relay to peer={:?}: {:?}", peer, e),
                Ok(_) => {
                    debug!("Tx relay to peer {:?} successful", peer);
                    success = true;
                }
            }
        }

        success
    }
}
