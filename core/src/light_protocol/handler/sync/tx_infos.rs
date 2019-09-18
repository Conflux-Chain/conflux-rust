// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;
extern crate lru_time_cache;

use cfx_types::H256;
use futures::Future;
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use primitives::{Receipt, SignedTransaction, TransactionAddress};
use std::sync::Arc;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers, UniqueId},
        message::{GetTxInfos, TxInfo},
        Error, ErrorKind,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        CACHE_TIMEOUT, MAX_TX_INFOS_IN_FLIGHT, TX_INFO_REQUEST_BATCH_SIZE,
        TX_INFO_REQUEST_TIMEOUT,
    },
};

use super::{
    common::{FutureItem, SyncManager, TimeOrdered},
    BlockTxs, Receipts,
};

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingTxInfo = TimeOrdered<H256>;

type TxInfoValidated = (SignedTransaction, Receipt, TransactionAddress);

pub struct TxInfos {
    // block tx sync manager
    block_txs: Arc<BlockTxs>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // receipt sync manager
    receipts: Arc<Receipts>,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingTxInfo>,

    // block txs received from full node
    verified: Arc<RwLock<LruCache<H256, TxInfoValidated>>>,
}

impl TxInfos {
    pub fn new(
        block_txs: Arc<BlockTxs>, consensus: Arc<ConsensusGraph>,
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        receipts: Arc<Receipts>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager = SyncManager::new(peers.clone());

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        TxInfos {
            block_txs,
            ledger,
            receipts,
            request_id_allocator,
            sync_manager,
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
    pub fn request_now(
        &self, io: &dyn NetworkContext, hash: H256,
    ) -> impl Future<Item = TxInfoValidated, Error = Error> {
        if !self.verified.read().contains_key(&hash) {
            let missing = std::iter::once(MissingTxInfo::new(hash));

            self.sync_manager.request_now(missing, |peer, hashes| {
                self.send_request(io, peer, hashes)
            });
        }

        FutureItem::new(hash, self.verified.clone())
    }

    #[inline]
    pub fn receive(
        &self, infos: impl Iterator<Item = TxInfo>,
    ) -> Result<(), Error> {
        for info in infos {
            info!("Validating tx_info {:?}", info);

            let TxInfo {
                epoch,
                block_hash,
                index: _,
                mut epoch_receipts,
                block_txs,
            } = info;

            // find index of block within epoch
            let hashes = self.ledger.block_hashes_in(epoch)?;
            let block_index = hashes.iter().position(|h| *h == block_hash);

            let block_index = match block_index {
                Some(index) => index,
                None => {
                    warn!(
                        "Block {:?} does not exist in epoch {} (hashes: {:?})",
                        block_hash, epoch, hashes
                    );
                    return Err(ErrorKind::InvalidTxInfo.into());
                }
            };

            // validate receipts
            let receipts = epoch_receipts.clone();
            self.receipts.receive_single(epoch, receipts)?;

            // validate block txs
            let txs = block_txs.clone();
            self.block_txs.receive_single(block_hash, txs)?;

            // `epoch_receipts` is valid and `block_hash` exists in epoch
            assert!(block_index < epoch_receipts.len());
            let block_receipts = epoch_receipts.swap_remove(block_index);

            // `block_txs` is valid and `block_hash` exists in epoch
            assert!(block_txs.len() == block_receipts.len());
            let items = block_txs.into_iter().zip(block_receipts.into_iter());

            for (index, (tx, receipt)) in items.enumerate() {
                let hash = tx.hash();
                let address = TransactionAddress { block_hash, index };
                self.verified.write().insert(hash, (tx, receipt, address));
                self.sync_manager.remove_in_flight(&hash);
            }
        }

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        let timeout = *TX_INFO_REQUEST_TIMEOUT;
        let infos = self.sync_manager.remove_timeout_requests(timeout);
        self.sync_manager.insert_waiting(infos.into_iter());
    }

    #[inline]
    fn send_request(
        &self, io: &dyn NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        info!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetTxInfos {
            request_id: self.request_id_allocator.next(),
            hashes,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("tx info sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_TX_INFOS_IN_FLIGHT,
            TX_INFO_REQUEST_BATCH_SIZE,
            |peer, hashes| self.send_request(io, peer, hashes),
        );
    }
}
