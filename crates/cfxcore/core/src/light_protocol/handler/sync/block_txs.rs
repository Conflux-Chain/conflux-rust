// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    Txs,
};
use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        error::*,
        message::{msgid, BlockTxsWithHash, GetBlockTxs},
    },
    message::{Message, RequestId},
    verification::compute_transaction_root,
    UniqueId,
};
use cfx_parameters::light::{
    BLOCK_TX_REQUEST_BATCH_SIZE, BLOCK_TX_REQUEST_TIMEOUT, CACHE_TIMEOUT,
    MAX_BLOCK_TXS_IN_FLIGHT,
};
use cfx_types::H256;
use futures::future::FutureExt;
use lru_time_cache::LruCache;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::SignedTransaction;
use std::{future::Future, sync::Arc};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingBlockTxs = TimeOrdered<H256>;

type PendingBlockTxs = PendingItem<Vec<SignedTransaction>, ClonableError>;

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
    verified: Arc<RwLock<LruCache<H256, PendingBlockTxs>>>,
}

impl BlockTxs {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>, txs: Arc<Txs>,
    ) -> Self {
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
    pub fn print_stats(&self) {
        debug!(
            "block tx sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    #[inline]
    pub fn request(
        &self, hash: H256,
    ) -> impl Future<Output = Result<Vec<SignedTransaction>>> {
        let mut verified = self.verified.write();

        if !verified.contains_key(&hash) {
            let missing = MissingBlockTxs::new(hash);
            self.sync_manager.insert_waiting(std::iter::once(missing));
        }

        verified
            .entry(hash)
            .or_insert(PendingItem::pending())
            .clear_error();

        FutureItem::new(hash, self.verified.clone())
            .map(|res| res.map_err(|e| e.into()))
    }

    #[inline]
    pub fn receive(
        &self, peer: &NodeId, id: RequestId,
        block_txs: impl Iterator<Item = BlockTxsWithHash>,
    ) -> Result<()> {
        for BlockTxsWithHash { hash, block_txs } in block_txs {
            trace!("Validating block_txs {:?} with hash {}", block_txs, hash);

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
    ) -> Result<()> {
        // validate block txs
        if let Err(e) = self.validate_block_txs(hash, &block_txs) {
            // forward error to both rpc caller(s) and sync handler
            // so we need to make it clonable
            let e = ClonableError::from(e);

            self.verified
                .write()
                .entry(hash)
                .or_insert(PendingItem::pending())
                .set_error(e.clone());

            bail!(e);
        }

        // store block bodies by block hash
        self.verified
            .write()
            .entry(hash)
            .or_insert(PendingItem::pending())
            .set(block_txs);

        self.sync_manager.remove_in_flight(&hash);
        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *BLOCK_TX_REQUEST_TIMEOUT;
        let block_txs = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout block-txs ({}): {:?}", block_txs.len(), block_txs);
        self.sync_manager.insert_waiting(block_txs.into_iter());

        // trigger cache cleanup
        self.verified.write().get(&Default::default());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: &NodeId, hashes: Vec<H256>,
    ) -> Result<Option<RequestId>> {
        if hashes.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        trace!(
            "send_request GetBlockTxs peer={:?} id={:?} hashes={:?}",
            peer,
            request_id,
            hashes
        );

        let msg: Box<dyn Message> =
            Box::new(GetBlockTxs { request_id, hashes });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_BLOCK_TXS_IN_FLIGHT,
            BLOCK_TX_REQUEST_BATCH_SIZE,
            |peer, block_hashes| self.send_request(io, peer, block_hashes),
        );
    }

    #[inline]
    pub fn validate_block_txs(
        &self, hash: H256, txs: &Vec<SignedTransaction>,
    ) -> Result<()> {
        // validate each transaction first
        for tx in txs {
            self.txs.validate_tx(&tx)?;
        }

        let expected = *self.ledger.header(hash)?.transactions_root();
        let txs: Vec<_> = txs.iter().map(|tx| Arc::new(tx.clone())).collect();
        let received = compute_transaction_root(&txs);

        if received != expected {
            bail!(Error::InvalidTxRoot {
                hash,
                expected,
                received,
            });
        }

        Ok(())
    }
}
