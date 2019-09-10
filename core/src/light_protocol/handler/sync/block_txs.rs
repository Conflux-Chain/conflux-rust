// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use cfx_types::H256;
use futures::Future;
use parking_lot::RwLock;
use primitives::{Block, SignedTransaction};
use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers, UniqueId},
        message::{BlockTxsWithHash, GetBlockTxs},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        BLOCK_TX_REQUEST_BATCH_SIZE, BLOCK_TX_REQUEST_TIMEOUT_MS,
        MAX_BLOCK_TXS_IN_FLIGHT,
    },
};

use super::{
    common::{FutureItem, SyncManager, TimeOrdered},
    Txs,
};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    verified: usize,
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
    verified: Arc<RwLock<HashMap<H256, Vec<SignedTransaction>>>>,
}

impl BlockTxs {
    pub fn new(
        consensus: Arc<ConsensusGraph>, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>, txs: Arc<Txs>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager = SyncManager::new(peers.clone());
        let verified = Arc::new(RwLock::new(HashMap::new()));

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
            in_flight: self.sync_manager.num_in_flight(),
            verified: self.verified.read().len(),
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
        &self, block_txs: impl Iterator<Item = BlockTxsWithHash>,
    ) -> Result<(), Error> {
        for BlockTxsWithHash { hash, block_txs } in block_txs {
            info!("Validating block_txs {:?} with hash {}", block_txs, hash);
            self.validate_block_txs(hash, &block_txs)?;

            // store each transaction by its hash
            self.txs.receive(block_txs.clone().into_iter())?;

            // store block bodies by block hash
            self.verified.write().insert(hash, block_txs);
            self.sync_manager.remove_in_flight(&hash);
        }

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = Duration::from_millis(BLOCK_TX_REQUEST_TIMEOUT_MS);
        let block_txs = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(block_txs.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetBlockTxs {
            request_id: self.request_id_allocator.next(),
            hashes,
        });

        msg.send(io, peer)?;
        Ok(())
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
        // first, validate signatures for each tx
        for tx in txs {
            match tx.verify_public(false /* skip */) {
                Ok(true) => continue,
                _ => {
                    warn!("Tx signature verification failed for {:?}", tx);
                    return Err(ErrorKind::InvalidTxSignature.into());
                }
            }
        }

        // then, compute tx root and match against header info
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
