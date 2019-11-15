// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;
extern crate lru_time_cache;

use cfx_types::H256;
use futures::Future;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use primitives::{Block, SignedTransaction};
use std::sync::Arc;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers, UniqueId},
        message::{msgid, BlockTxsWithHash, GetBlockTxs},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{
        BLOCK_TX_REQUEST_BATCH_SIZE, BLOCK_TX_REQUEST_TIMEOUT, CACHE_TIMEOUT,
        MAX_BLOCK_TXS_IN_FLIGHT,
    },
};

use super::{
    common::{FutureItem, SyncManager, TimeOrdered},
    Txs,
};

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingBlockTxs = TimeOrdered<H256>;

pub struct BlockTxs {
    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingBlockTxs>,

    // tx sync manager
    txs: Arc<Txs>,

    // block txs received from full node
    verified: Arc<RwLock<LruCache<H256, Vec<SignedTransaction>>>>,
}

impl BlockTxs {
    pub fn new(
        consensus: Arc<ConsensusGraph>, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>, txs: Arc<Txs>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager =
            SyncManager::new(peers.clone(), msgid::GET_BLOCK_TXS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        BlockTxs {
            ledger,
            request_id_allocator,
            sync_manager,
            txs,
            verified,
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
    pub fn request(
        &self, hash: H256,
    ) -> impl Future<Item = Vec<SignedTransaction>, Error = Error> {
        if !self.verified.read().contains_key(&hash) {
            let missing = MissingBlockTxs::new(hash);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        FutureItem::new(hash, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, peer: PeerId, id: RequestId,
        block_txs: impl Iterator<Item = BlockTxsWithHash>,
    ) -> Result<(), Error>
    {
        for BlockTxsWithHash { hash, block_txs } in block_txs {
            info!("Validating block_txs {:?} with hash {}", block_txs, hash);

            match self.sync_manager.check_if_requested(peer, id, &hash)? {
                None => continue,
                Some(_) => self.validate_and_store(hash, block_txs)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(
        &self, hash: H256, block_txs: Vec<SignedTransaction>,
    ) -> Result<(), Error> {
        // validate and store each transaction
        for tx in &block_txs {
            self.txs.validate_and_store(tx.clone())?;
        }

        // validate block txs
        self.validate_block_txs(hash, &block_txs)?;

        // store block bodies by block hash
        self.verified.write().insert(hash, block_txs);
        self.sync_manager.remove_in_flight(&hash);

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *BLOCK_TX_REQUEST_TIMEOUT;
        let block_txs = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(block_txs.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<Option<RequestId>, Error> {
        info!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> =
            Box::new(GetBlockTxs { request_id, hashes });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("block tx sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_BLOCK_TXS_IN_FLIGHT,
            BLOCK_TX_REQUEST_BATCH_SIZE,
            |peer, block_hashes| self.send_request(io, peer, block_hashes),
        );
    }

    #[inline]
    pub fn validate_block_txs(
        &self, hash: H256, txs: &Vec<SignedTransaction>,
    ) -> Result<(), Error> {
        // NOTE: tx signatures have been validated previously

        let local = *self.ledger.header(hash)?.transactions_root();

        let txs: Vec<_> = txs.iter().map(|tx| Arc::new(tx.clone())).collect();
        let received = Block::compute_transaction_root(&txs);

        if received != local {
            warn!(
                "Tx root validation failed, received={:?}, local={:?}",
                received, local
            );
            return Err(ErrorKind::InvalidTxRoot.into());
        }

        Ok(())
    }
}
