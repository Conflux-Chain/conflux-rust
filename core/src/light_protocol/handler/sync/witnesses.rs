// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::common::{KeyReverseOrdered, LedgerProof, SyncManager};
use crate::{
    block_data_manager::{
        block_data_types::BlamedHeaderVerifiedRoots, BlockDataManager,
    },
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        error::*,
        message::{msgid, GetWitnessInfo, WitnessInfoWithHeight},
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    light::{
        MAX_WITNESSES_IN_FLIGHT, WITNESS_REQUEST_BATCH_SIZE,
        WITNESS_REQUEST_TIMEOUT,
    },
};
use cfx_types::H256;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use std::{collections::HashSet, sync::Arc};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: u64,
    waiting: usize,
}

#[derive(Debug)]
pub struct VerifiedRoots {
    pub state_root_hash: H256,
    pub receipts_root_hash: H256,
    pub logs_bloom_hash: H256,
}

impl From<BlamedHeaderVerifiedRoots> for VerifiedRoots {
    fn from(roots: BlamedHeaderVerifiedRoots) -> Self {
        Self {
            state_root_hash: roots.deferred_state_root,
            receipts_root_hash: roots.deferred_receipts_root,
            logs_bloom_hash: roots.deferred_logs_bloom_hash,
        }
    }
}

// prioritize lower epochs
type MissingWitness = KeyReverseOrdered<u64>;

pub struct Witnesses {
    // block data manager
    data_man: Arc<BlockDataManager>,

    // height of the latest header for which we have trusted information
    pub height_of_latest_verified_header: RwLock<u64>,

    // collection used to track the heights for which we have requested
    // witnesses. e.g. if header 3 is blamed by header 4, we will request
    // witness 4 and insert both 3 and 4 into `in_flight` (as opposed to
    // `sync_manager.in_flight` that will only contain 4).
    pub in_flight: RwLock<HashSet<u64>>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingWitness>,
}

impl Witnesses {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let data_man = consensus.get_data_manager().clone();
        let height_of_latest_verified_header = RwLock::new(0);
        let in_flight = RwLock::new(HashSet::new());
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_WITNESS_INFO);

        Witnesses {
            data_man,
            height_of_latest_verified_header,
            in_flight,
            ledger,
            request_id_allocator,
            sync_manager,
        }
    }

    #[inline]
    pub fn latest_verified(&self) -> u64 {
        *self.height_of_latest_verified_header.read()
    }

    pub fn print_stats(&self) {
        trace!(
            "witness sync statistics: {:?}",
            Statistics {
                in_flight: self.sync_manager.num_in_flight(),
                verified: self.latest_verified(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    /// Get root hashes for `epoch` from local cache.
    #[inline]
    pub fn root_hashes_of(&self, epoch: u64) -> Result<VerifiedRoots> {
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;

        if height > *self.height_of_latest_verified_header.read() {
            bail!(ErrorKind::WitnessUnavailable { epoch });
        }

        match self.data_man.verified_blamed_roots_by_height(height) {
            Some(roots) => Ok(roots.into()),
            None => {
                // we set `height_of_latest_verified_header` before receiving
                // the response for blamed headers. thus, in some cases, `None`
                // might mean *haven't received yet* instead of *not blamed*.
                if self.in_flight.read().contains(&height) {
                    bail!(ErrorKind::WitnessUnavailable { epoch });
                }

                let header = self
                    .ledger
                    .pivot_header_of(height)
                    .expect("pivot header should exist");

                Ok(VerifiedRoots {
                    state_root_hash: *header.deferred_state_root(),
                    receipts_root_hash: *header.deferred_receipts_root(),
                    logs_bloom_hash: *header.deferred_logs_bloom_hash(),
                })
            }
        }
    }

    #[inline]
    pub fn request(&self, witness: u64) {
        let blame = self
            .ledger
            .pivot_header_of(witness)
            .expect("Pivot header should exist")
            .blame() as u64;

        let mut in_flight = self.in_flight.write();

        for h in (witness - blame)..=witness {
            in_flight.insert(h);
        }

        let missing = MissingWitness::new(witness);
        self.sync_manager.insert_waiting(std::iter::once(missing));
    }

    fn handle_witness_info(&self, item: WitnessInfoWithHeight) -> Result<()> {
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

        // if we only get one root, that means that the witness is not blaming
        // any previous headers.
        if state_roots.len() == 1 {
            error!("Received witness info of length 1 for height {}", witness);
            return Ok(());
        }

        let mut in_flight = self.in_flight.write();

        // handle valid hashes
        for ii in 0..state_roots.len() as u64 {
            // find corresponding epoch
            let height = witness - ii;

            // insert into db
            let r = BlamedHeaderVerifiedRoots {
                deferred_state_root: state_roots[ii as usize],
                deferred_receipts_root: receipts[ii as usize],
                deferred_logs_bloom_hash: blooms[ii as usize],
            };

            self.data_man.insert_blamed_header_verified_roots(height, r);

            // signal receipt
            in_flight.remove(&height);
        }

        Ok(())
    }

    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        witnesses: impl Iterator<Item = WitnessInfoWithHeight>,
    ) -> Result<()>
    {
        for item in witnesses {
            trace!("Validating witness info {:?}", item);

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
    ) -> Result<()> {
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
        trace!("Timeout witnesses ({}): {:?}", witnesses.len(), witnesses);
        self.sync_manager.insert_waiting(witnesses.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, witnesses: Vec<u64>,
    ) -> Result<Option<RequestId>> {
        if witnesses.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        trace!(
            "send_request GetWitnessInfo peer={:?} id={:?} witnesses={:?}",
            peer,
            request_id,
            witnesses
        );

        let msg: Box<dyn Message> = Box::new(GetWitnessInfo {
            request_id,
            witnesses,
        });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_WITNESSES_IN_FLIGHT,
            WITNESS_REQUEST_BATCH_SIZE,
            |peer, witnesses| self.send_request(io, peer, witnesses),
        );
    }
}
