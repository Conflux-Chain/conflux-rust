// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    cmp,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{LedgerInfo, LedgerProof, Peers, UniqueId},
        handler::FullPeerState,
        message::{GetWitnessInfo, WitnessInfoWithHeight},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{
            BLAME_CHECK_OFFSET, MAX_WITNESSES_IN_FLIGHT,
            NUM_WAITING_WITNESSES_THRESHOLD, WITNESS_REQUEST_BATCH_SIZE,
            WITNESS_REQUEST_TIMEOUT_MS,
        },
    },
};

use super::{
    blooms::Blooms,
    sync_manager::{HasKey, SyncManager},
};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: u64,
    waiting: usize,
}

#[derive(Clone, Debug, Eq)]
pub(super) struct MissingWitness {
    pub height: u64,
    pub since: Instant,
}

impl MissingWitness {
    pub fn new(height: u64) -> Self {
        MissingWitness {
            height,
            since: Instant::now(),
        }
    }
}

impl PartialEq for MissingWitness {
    fn eq(&self, other: &Self) -> bool { self.height == other.height }
}

// MissingWitness::cmp is used for prioritizing header requests
impl Ord for MissingWitness {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self.eq(other) {
            return cmp::Ordering::Equal;
        }

        let cmp_since = self.since.cmp(&other.since).reverse();
        let cmp_height = self.height.cmp(&other.height);

        cmp_since.then(cmp_height)
    }
}

impl PartialOrd for MissingWitness {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl HasKey<u64> for MissingWitness {
    fn key(&self) -> u64 { self.height }
}

pub(super) struct Witnesses {
    // bloom sync manager
    blooms: Arc<Blooms>,

    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // latest header for which we have trusted information
    latest_verified_header: RwLock<u64>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<u64, MissingWitness>,
}

impl Witnesses {
    pub fn new(
        blooms: Arc<Blooms>, consensus: Arc<ConsensusGraph>,
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let latest_verified_header = RwLock::new(0);
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager = SyncManager::new(peers.clone());

        Witnesses {
            blooms,
            consensus,
            latest_verified_header,
            ledger,
            request_id_allocator,
            sync_manager,
        }
    }

    #[inline]
    fn get_statistics(&self) -> Statistics {
        Statistics {
            in_flight: self.sync_manager.num_in_flight(),
            verified: *self.latest_verified_header.read(),
            waiting: self.sync_manager.num_waiting(),
        }
    }

    #[inline]
    pub fn request<I>(&self, witnesses: I)
    where I: Iterator<Item = u64> {
        let witnesses = witnesses.map(|h| MissingWitness::new(h));
        self.sync_manager.insert_waiting(witnesses);
    }

    pub fn receive<I>(&self, witnesses: I) -> Result<(), Error>
    where I: Iterator<Item = WitnessInfoWithHeight> {
        for item in witnesses {
            let witness = item.height;
            let receipts = item.receipt_hashes;
            let blooms = item.bloom_hashes;

            // validate hashes
            let header = self.ledger.pivot_header_of(witness)?;
            LedgerProof::ReceiptsRoot(receipts.clone()).validate(&header)?;
            LedgerProof::LogsBloomHash(blooms.clone()).validate(&header)?;

            // the previous validation should not pass if this is not true
            assert!(receipts.len() == blooms.len());

            // handle valid hashes
            for ii in 0..blooms.len() as u64 {
                // find corresponding epoch
                let height = witness - ii;
                let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);

                // store receipts root and logs bloom hash
                self.consensus.data_man.insert_epoch_execution_commitments(
                    self.ledger.pivot_hash_of(epoch)?,
                    receipts[ii as usize],
                    blooms[ii as usize],
                );

                // request bloom for this epoch
                self.blooms.request(epoch);
            }

            // signal receipt
            self.sync_manager.remove_in_flight(&witness);
        }

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = Duration::from_millis(WITNESS_REQUEST_TIMEOUT_MS);
        let witnesses = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(witnesses.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, witnesses: Vec<u64>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} witnesses={:?}", peer, witnesses);

        if witnesses.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetWitnessInfo {
            request_id: self.request_id_allocator.next(),
            witnesses,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("witness sync statistics: {:?}", self.get_statistics());

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
    fn is_header_trusted(&self, height: u64) -> Result<bool, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.ledger.pivot_hash_of(epoch)?;

        Ok(!self.is_blamed(height)
            || self
                .consensus
                .data_man
                .get_epoch_execution_commitments(&pivot)
                .is_some())
    }

    fn verify_pivot_chain(&self) -> Result<(), Error> {
        let best = self.consensus.best_epoch_number() - BLAME_CHECK_OFFSET;
        let mut latest = self.latest_verified_header.write();

        let mut height = *latest + 1;

        // iterate through all trusted pivot headers
        // TODO(thegaram): consider chain-reorg
        while height < best && self.is_header_trusted(height)? {
            debug!("header {} is valid", height);

            let header = self.ledger.pivot_header_of(height)?;
            let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);

            // for blamed and blaming blocks, we've stored the correct roots in
            // the `on_witness_info` response handler
            if !self.is_blamed(height) && header.blame() == 0 {
                self.consensus.data_man.insert_epoch_execution_commitments(
                    self.ledger.pivot_hash_of(epoch)?,
                    *header.deferred_receipts_root(),
                    *header.deferred_logs_bloom_hash(),
                );
            }

            // request corresponding bloom
            self.blooms.request(epoch);

            *latest = height;
            height += 1;
        }

        Ok(())
    }

    fn collect_witnesses(&self) -> Result<(), Error> {
        let best = self.consensus.best_epoch_number() - BLAME_CHECK_OFFSET;
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
                    return Err(ErrorKind::InternalError.into());
                }
            };

            debug!("header {} is NOT valid, witness: {}", height, witness);
            self.request(std::iter::once(witness));

            height = witness + 1;
        }

        Ok(())
    }
}
