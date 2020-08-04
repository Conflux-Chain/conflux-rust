// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use parking_lot::RwLock;
use std::sync::Arc;

use crate::{
    block_data_manager::{
        block_data_types::BlamedHeaderVerifiedRoots, BlockDataManager,
    },
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

// TODO(thegaram): consider adding a cache for recent blamed headers
pub struct Witnesses {
    // block data manager
    data_man: Arc<BlockDataManager>,

    // latest header for which we have trusted information
    pub latest_verified_header: RwLock<u64>,

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
        let latest_verified_header = RwLock::new(0);
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_WITNESS_INFO);

        Witnesses {
            data_man,
            latest_verified_header,
            ledger,
            request_id_allocator,
            sync_manager,
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
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;

        if height > *self.latest_verified_header.read() {
            return None;
        }

        match self.data_man.verified_blamed_roots_by_height(height) {
            Some(roots) => {
                // TODO(thegaram): consider case when there's a chain reorg and
                // recent blocks' blame status changes; we need avoid serving
                // stale roots from db; maybe explicitly remove all non-blamed
                // blocks from db?
                //
                //                 blame
                //              ............
                //              v          |
                //             ---        ---
                //         .- | B | <--- | C | <--- ...
                //  ---    |   ---        ---
                // | A | <-*
                //  ---    |   ---
                //         .- | D | <--- ...
                //             ---
                //              ^
                //          height = X
                //
                // we receive A, B, C, ..., A, D (chain reorg);
                // we stored the verified roots of B on disk;
                // after chain reorg, height X's blame status changes
                // --> need to make sure to serve correct roots directly from
                //     header D instead of the stale roots retrieved for B

                Some(roots.into_tuple())
            }
            None => {
                // we set `latest_verified_header` before receiving the
                // response for blamed headers. thus, in some cases, `None`
                // might mean *haven't received yet* instead of *not blamed*.
                // TODO(thegaram): add mechanism to detect such race condition
                if self.sync_manager.contains(&height) {
                    // FIXME(thegaram): if `height - 1` is blamed by `height`,
                    // sync manager will not contain `height - 1` but it will
                    // still be incorrect to get it from disk
                    error!("Witness {} still in flight!", height);
                    panic!("Witness requested still in flight!");
                }

                let header = self
                    .ledger
                    .pivot_header_of(height)
                    .expect("pivot header should exist");

                Some((
                    *header.deferred_state_root(),
                    *header.deferred_receipts_root(),
                    *header.deferred_logs_bloom_hash(),
                ))
            }
        }
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
        for ii in 0..state_roots.len() as u64 {
            // find corresponding epoch
            let height = witness - ii;

            let r = BlamedHeaderVerifiedRoots {
                deferred_state_root: state_roots[ii as usize],
                deferred_receipts_root: receipts[ii as usize],
                deferred_logs_bloom_hash: blooms[ii as usize],
            };

            self.data_man.insert_blamed_header_verified_roots(height, r);
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
