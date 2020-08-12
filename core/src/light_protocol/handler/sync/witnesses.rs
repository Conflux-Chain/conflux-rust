// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::common::{KeyReverseOrdered, LedgerProof, SyncManager};
use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        message::{msgid, GetWitnessInfo, WitnessInfoWithHeight},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    light::{
        BLAME_CHECK_OFFSET, MAX_WITNESSES_IN_FLIGHT,
        NUM_WAITING_WITNESSES_THRESHOLD, WITNESS_REQUEST_BATCH_SIZE,
        WITNESS_REQUEST_TIMEOUT,
    },
};
use cfx_types::H256;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: u64,
    waiting: usize,
}

// prioritize lower epochs
type MissingWitness = KeyReverseOrdered<u64>;

pub struct Witnesses {
    // shared consensus graph
    consensus: SharedConsensusGraph,

    // latest header for which we have trusted information
    latest_verified_header: RwLock<u64>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingWitness>,

    // roots received from full node
    // (state_root_hash, receipts_root_hash, logs_bloom_hash)
    verified: RwLock<HashMap<u64, (H256, H256, H256)>>,
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
            consensus,
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
        let state_roots = item.state_root_hashes;
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

        if let Err(e) = self.verify_pivot_chain() {
            warn!("Failed to verify pivot chain: {:?}", e);
            return;
        }

        if let Err(e) = self.collect_witnesses() {
            warn!("Failed to collect witnesses: {:?}", e);
            return;
        }

        self.sync_manager.sync(
            MAX_WITNESSES_IN_FLIGHT,
            WITNESS_REQUEST_BATCH_SIZE,
            |peer, witnesses| self.send_request(io, peer, witnesses),
        );
    }

    #[inline]
    fn is_blamed(&self, height: u64) -> bool {
        self.ledger.witness_of_header_at(height) != Some(height)
    }

    // a header is trusted if
    //     a) it is not blamed (i.e. it is its own witness)
    //     b) we have received and validated the corresponding root
    #[inline]
    fn is_header_trusted(&self, height: u64) -> bool {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        !self.is_blamed(height) || self.verified.read().contains_key(&epoch)
    }

    fn verify_pivot_chain(&self) -> Result<(), Error> {
        let best = match self.consensus.best_epoch_number() {
            epoch if epoch < BLAME_CHECK_OFFSET => return Ok(()),
            epoch => epoch - BLAME_CHECK_OFFSET,
        };

        let mut latest = self.latest_verified_header.write();
        let mut height = *latest + 1;

        // iterate through all trusted pivot headers
        // TODO(thegaram): consider chain-reorg
        while height < best && self.is_header_trusted(height) {
            trace!("header {} is valid", height);
            let header = self.ledger.pivot_header_of(height)?;
            let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);

            // for blamed and blaming blocks, we've stored the correct roots in
            // the `on_witness_info` response handler
            if !self.is_blamed(height) && header.blame() == 0 {
                self.verified.write().insert(
                    epoch,
                    (
                        *header.deferred_state_root(),
                        *header.deferred_receipts_root(),
                        *header.deferred_logs_bloom_hash(),
                    ),
                );
            }

            *latest = height;
            height += 1;
        }

        Ok(())
    }

    fn collect_witnesses(&self) -> Result<(), Error> {
        let best = match self.consensus.best_epoch_number() {
            epoch if epoch < BLAME_CHECK_OFFSET => return Ok(()),
            epoch => epoch - BLAME_CHECK_OFFSET,
        };

        let mut height = *self.latest_verified_header.read() + 1;

        while height <= best
            && self.sync_manager.num_waiting() < NUM_WAITING_WITNESSES_THRESHOLD
        {
            // header trusted
            if !self.is_blamed(height) {
                height += 1;
                continue;
            }

            // header not trusted
            let witness = match self.ledger.witness_of_header_at(height) {
                Some(w) => w,
                None => {
                    warn!("Unable to get witness!");
                    bail!(ErrorKind::InternalError(format!(
                        "Witness at height {} is not available",
                        height
                    )));
                }
            };

            debug!("header {} is NOT valid, witness: {}", height, witness);
            self.request(std::iter::once(witness));

            height = witness + 1;
        }

        Ok(())
    }
}
