// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        message::{msgid, GetWitnessInfo, WitnessInfoWithHeight},
        Error,
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{
            MAX_WITNESSES_IN_FLIGHT, WITNESS_REQUEST_BATCH_SIZE,
            WITNESS_REQUEST_TIMEOUT,
        },
    },
    UniqueId,
};

use super::common::{KeyReverseOrdered, LedgerProof, SyncManager};
use network::node_table::NodeId;

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: u64,
    waiting: usize,
}

// prioritize lower epochs
type MissingWitness = KeyReverseOrdered<u64>;

pub struct Witnesses {
    // latest header for which we have trusted information
    pub latest_verified_header: RwLock<u64>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingWitness>,

    // roots received from full node
    // (state_root_hash, receipts_root_hash, logs_bloom_hash)
    pub verified: RwLock<HashMap<u64, (H256, H256, H256)>>,
}

impl Witnesses {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let latest_verified_header = RwLock::new(0);
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_WITNESS_INFO);
        let verified = RwLock::new(HashMap::new());

        Witnesses {
            latest_verified_header,
            ledger,
            request_id_allocator,
            sync_manager,
            verified,
        }
    }

    #[inline]
    pub fn latest_verified(&self) -> u64 { *self.latest_verified_header.read() }

    fn get_statistics(&self) -> Statistics {
        Statistics {
            in_flight: self.sync_manager.num_in_flight(),
            verified: self.latest_verified(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    /// Get root hashes for `epoch` from local cache.
    #[inline]
    pub fn root_hashes_of(&self, epoch: u64) -> Option<(H256, H256, H256)> {
        self.verified.read().get(&epoch).cloned()
    }

    #[inline]
    pub fn request<I>(&self, witnesses: I)
    where I: Iterator<Item = u64> {
        let witnesses = witnesses.map(|h| MissingWitness::new(h));
        self.sync_manager.insert_waiting(witnesses);
    }

    fn handle_witness_info(
        &self, item: WitnessInfoWithHeight,
    ) -> Result<(), Error> {
        let witness = item.height;
        let state_roots = item.state_roots;
        let receipts = item.receipt_hashes;
        let blooms = item.bloom_hashes;

        // validate hashes
        let header = self.ledger.pivot_header_of(witness)?;
        LedgerProof::StateRoot(state_roots.clone()).validate(&header)?;
        LedgerProof::ReceiptsRoot(receipts.clone()).validate(&header)?;
        LedgerProof::LogsBloomHash(blooms.clone()).validate(&header)?;

        // the previous validation should not pass if this is not true
        assert!(state_roots.len() == receipts.len());
        assert!(receipts.len() == blooms.len());

        // handle valid hashes
        let mut verified = self.verified.write();

        for ii in 0..state_roots.len() as u64 {
            // find corresponding epoch
            let height = witness - ii;
            let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);

            // store receipts root and logs bloom hash
            verified.insert(
                epoch,
                (
                    state_roots[ii as usize],
                    receipts[ii as usize],
                    blooms[ii as usize],
                ),
            );
        }

        Ok(())
    }

    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        witnesses: impl Iterator<Item = WitnessInfoWithHeight>,
    ) -> Result<(), Error>
    {
        for item in witnesses {
            debug!("Validating witness info {:?}", item);

            match self.sync_manager.check_if_requested(
                peer,
                id,
                &item.height,
            )? {
                None => continue,
                Some(_) => self.validate_and_store(item)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, item: WitnessInfoWithHeight,
    ) -> Result<(), Error> {
        let witness = item.height;

        // validate and store
        self.handle_witness_info(item)?;

        // signal receipt
        self.sync_manager.remove_in_flight(&witness);

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = *WITNESS_REQUEST_TIMEOUT;
        let witnesses = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(witnesses.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, witnesses: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        debug!("send_request peer={:?} witnesses={:?}", peer, witnesses);

        if witnesses.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        let msg: Box<dyn Message> = Box::new(GetWitnessInfo {
            request_id,
            witnesses,
        });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        debug!("witness sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_WITNESSES_IN_FLIGHT,
            WITNESS_REQUEST_BATCH_SIZE,
            |peer, witnesses| self.send_request(io, peer, witnesses),
        );
    }
}
