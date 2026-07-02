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
#[allow(dead_code)]
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
    ) -> Self {
        let data_man = consensus.data_manager().clone();
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
            bail!(Error::WitnessUnavailable { epoch });
        }

        match self.data_man.verified_blamed_roots_by_height(height) {
            Some(roots) => Ok(roots.into()),
            None => {
                // we set `height_of_latest_verified_header` before receiving
                // the response for blamed headers. thus, in some cases, `None`
                // might mean *haven't received yet* instead of *not blamed*.
                if self.in_flight.read().contains(&height) {
                    bail!(Error::WitnessUnavailable { epoch });
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

    /// Lowest pivot height the header at `witness` vouches for (`witness -
    /// blame`), or `None` if malformed. `blame` is unbounded and unchecked at
    /// acceptance; a correct header never blames genesis, so `blame < witness`.
    /// `None` replaces an underflow panic on bad input.
    fn lowest_blamed_height(witness: u64, blame: u64) -> Option<u64> {
        match witness.checked_sub(blame) {
            Some(start) if start >= 1 => Some(start),
            _ => None,
        }
    }

    #[inline]
    pub fn request(&self, first_blamed_height: u64, witness: u64) {
        // Mark the blamed range in-flight (so `root_hashes_of` reports it
        // unavailable until verified) from the authoritative lower bound, not
        // `witness - header.blame()`: `blame` is unchecked and could underflow.
        {
            let mut in_flight = self.in_flight.write();
            for h in first_blamed_height..=witness {
                in_flight.insert(h);
            }
        }

        let blame = self
            .ledger
            .pivot_header_of(witness)
            .expect("Pivot header should exist")
            .blame() as u64;

        // A malformed local header can't be satisfied by an honest peer, and
        // requesting it would demote peers whose valid response fails to match
        // it. Leave the range in-flight (unavailable) until a reorg
        // re-verifies.
        if Self::lowest_blamed_height(witness, blame).is_none() {
            debug!(
                "Not requesting witness at height {}: local pivot header blames \
                 genesis or earlier (blame = {})",
                witness, blame
            );
            return;
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

        // `witness - ii` below underflows if `blame >= witness`, which means
        // our *local* header is malformed (e.g. after a reorg the proof
        // happens to match) — local invalid state, not peer misconduct,
        // so skip without punishing the peer.
        let blame = header.blame() as u64;
        if Self::lowest_blamed_height(witness, blame).is_none() {
            debug!(
                "Skipping witness info at height {}: local pivot header blames \
                 genesis or earlier (blame = {})",
                witness, blame
            );
            return Ok(());
        }

        let mut in_flight = self.in_flight.write();

        // handle valid hashes
        for ii in 0..state_roots.len() as u64 {
            // find corresponding epoch (safe: `witness > blame`, guarded above)
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
    ) -> Result<()> {
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

#[cfg(test)]
mod blame_underflow_tests {
    use super::Witnesses;

    // The raw `witness - blame` this fix replaced panics under
    // `overflow-checks` when `blame >= witness`. `black_box` forces a
    // runtime subtraction (not a compile-time `arithmetic_overflow` error),
    // matching the header-fed path.
    #[test]
    #[should_panic]
    fn raw_subtraction_underflows_on_malformed_blame() {
        let witness = std::hint::black_box(100u64);
        let blame = std::hint::black_box(200u64);
        let _ = witness - blame;
    }

    #[test]
    fn lowest_blamed_height_matches_raw_on_honest_inputs() {
        for &(witness, blame) in
            &[(100u64, 0u64), (100, 1), (100, 3), (100, 99)]
        {
            assert_eq!(
                Witnesses::lowest_blamed_height(witness, blame),
                Some(witness - blame),
                "witness={witness} blame={blame}",
            );
        }
    }

    #[test]
    fn lowest_blamed_height_none_on_malformed_blame() {
        // blame > witness: raw `witness - blame` would underflow
        assert_eq!(Witnesses::lowest_blamed_height(100, 200), None);
        assert_eq!(Witnesses::lowest_blamed_height(3, u32::MAX as u64), None);
        // blame == witness: would blame the genesis block (height 0)
        assert_eq!(Witnesses::lowest_blamed_height(100, 100), None);
        assert_eq!(Witnesses::lowest_blamed_height(0, 0), None);
        // blame == witness - 1: lowest blamed height is 1, just above genesis
        assert_eq!(Witnesses::lowest_blamed_height(100, 99), Some(1));
    }
}
