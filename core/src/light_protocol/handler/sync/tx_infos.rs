// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate lru_time_cache;

use cfx_types::{H256, U256};
use lru_time_cache::LruCache;
use parking_lot::RwLock;
use primitives::{Receipt, SignedTransaction, TransactionIndex};
use std::{future::Future, sync::Arc};

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    Witnesses,
};
use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        message::{msgid, GetTxInfos, TxInfo},
        Error, ErrorKind,
    },
    message::{Message, RequestId},
    network::NetworkContext,
    parameters::light::{
        CACHE_TIMEOUT, MAX_TX_INFOS_IN_FLIGHT, TX_INFO_REQUEST_BATCH_SIZE,
        TX_INFO_REQUEST_TIMEOUT,
    },
    verification::{
        is_valid_receipt_inclusion_proof, is_valid_tx_inclusion_proof,
    },
    UniqueId,
};
use network::node_table::NodeId;

#[derive(Debug)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingTxInfo = TimeOrdered<H256>;

// FIXME: struct
pub type TxInfoValidated = (SignedTransaction, Receipt, TransactionIndex, U256);

pub struct TxInfos {
    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingTxInfo>,

    // block txs received from full node
    verified: Arc<RwLock<LruCache<H256, PendingItem<TxInfoValidated>>>>,

    // witness sync manager
    pub witnesses: Arc<Witnesses>,
}

impl TxInfos {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>, witnesses: Arc<Witnesses>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let sync_manager = SyncManager::new(peers.clone(), msgid::GET_TX_INFOS);

        let cache = LruCache::with_expiry_duration(*CACHE_TIMEOUT);
        let verified = Arc::new(RwLock::new(cache));

        TxInfos {
            ledger,
            request_id_allocator,
            sync_manager,
            verified,
            witnesses,
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
    ) -> impl Future<Output = TxInfoValidated> {
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
        &self, peer: &NodeId, id: RequestId,
        infos: impl Iterator<Item = TxInfo>,
    ) -> Result<(), Error>
    {
        for info in infos {
            debug!("Validating tx_info {:?}", info);

            match self.sync_manager.check_if_requested(
                peer,
                id,
                &info.tx.hash(),
            )? {
                None => continue,
                Some(_) => self.validate_and_store(info)?,
            };
        }

        Ok(())
    }

    #[inline]
    pub fn validate_and_store(&self, info: TxInfo) -> Result<(), Error> {
        let TxInfo {
            epoch,

            // tx-related fields
            tx,
            tx_index_in_block,
            num_txs_in_block,
            tx_proof,

            // receipt-related fields
            receipt,
            block_index_in_epoch,
            num_blocks_in_epoch,
            block_index_proof,
            receipt_proof,

            // prior_gas_used-related fields
            maybe_prev_receipt,
            maybe_prev_receipt_proof,
        } = info;

        // quick check for well-formedness
        if block_index_in_epoch >= num_blocks_in_epoch {
            debug!(
                "Inconsisent block index: {} >= {}",
                block_index_in_epoch, num_blocks_in_epoch
            );
            return Err(ErrorKind::InvalidTxInfo.into());
        }

        if tx_index_in_block >= num_txs_in_block {
            debug!(
                "Inconsisent tx index: {} >= {}",
                tx_index_in_block, num_txs_in_block
            );
            return Err(ErrorKind::InvalidTxInfo.into());
        }

        // only executed instances of the transaction are acceptable;
        // receipts belonging to non-executed instances should not be sent
        if receipt.outcome_status != 0 && receipt.outcome_status != 1 {
            debug!(
                "Unexpected outcome status in tx info: {}",
                receipt.outcome_status
            );
            return Err(ErrorKind::InvalidTxInfo.into());
        }

        let block_hash = match self.ledger.block_hashes_in(epoch)? {
            hs if hs.len() != num_blocks_in_epoch => {
                debug!("Number of blocks in epoch mismatch: local = {}, received = {}", hs.len(), num_blocks_in_epoch);
                return Err(ErrorKind::InvalidTxInfo.into());
            }
            hs => hs[block_index_in_epoch],
        };

        // verify tx proof
        let tx_hash = tx.hash();
        let block_tx_root =
            *self.ledger.header(block_hash)?.transactions_root();

        trace!(
            "verifying tx proof with\n
            block_tx_root = {:?}\n
            tx_index_in_block = {:?}\n
            num_txs_in_block = {:?}\n
            tx_hash = {:?}\n
            tx_proof = {:?}",
            block_tx_root,
            tx_index_in_block,
            num_txs_in_block,
            tx_hash,
            tx_proof
        );

        if !is_valid_tx_inclusion_proof(
            block_tx_root,
            tx_index_in_block,
            num_txs_in_block,
            tx_hash,
            &tx_proof,
        ) {
            debug!("Transaction proof verification failed");
            return Err(ErrorKind::InvalidTxInfo.into());
        }

        // verify receipt proof
        let verified_epoch_receipts_root =
            match self.witnesses.root_hashes_of(epoch) {
                Some((_, receipts_root, _)) => receipts_root,
                None => {
                    // TODO(thegaram): signal to RPC layer that the
                    // corresponding roots are not available yet
                    warn!("Receipt root not found, epoch={}", epoch,);
                    return Err(ErrorKind::InternalError.into());
                }
            };

        trace!(
            "verifying receipt proof with\n
            verified_epoch_receipts_root = {:?}\n
            block_index_in_epoch = {:?}\n
            num_blocks_in_epoch = {:?}\n
            block_index_proof = {:?}\n
            tx_index_in_block = {:?}\n
            num_txs_in_block = {:?}\n
            receipt = {:?}\n
            receipt_proof = {:?}",
            verified_epoch_receipts_root,
            block_index_in_epoch,
            num_blocks_in_epoch,
            block_index_proof,
            tx_index_in_block,
            num_txs_in_block,
            receipt,
            receipt_proof,
        );

        if !is_valid_receipt_inclusion_proof(
            verified_epoch_receipts_root,
            block_index_in_epoch,
            num_blocks_in_epoch,
            &block_index_proof,
            tx_index_in_block,
            num_txs_in_block,
            &receipt,
            &receipt_proof,
        ) {
            debug!("Receipt proof verification failed");
            return Err(ErrorKind::InvalidTxInfo.into());
        }

        // find prior gas used
        let prior_gas_used = match (
            tx_index_in_block,
            maybe_prev_receipt,
            maybe_prev_receipt_proof,
        ) {
            // first receipt in block
            (0, _, _) => U256::zero(),

            // not the first receipt so we will use the previous receipt
            (_n, Some(prev_receipt), Some(prev_receipt_proof)) => {
                let prev_receipt_index = tx_index_in_block - 1;

                if !is_valid_receipt_inclusion_proof(
                    verified_epoch_receipts_root,
                    block_index_in_epoch,
                    num_blocks_in_epoch,
                    &block_index_proof,
                    prev_receipt_index,
                    num_txs_in_block,
                    &prev_receipt,
                    &prev_receipt_proof,
                ) {
                    debug!("Receipt proof verification failed");
                    return Err(ErrorKind::InvalidTxInfo.into());
                }

                prev_receipt.accumulated_gas_used
            }

            // not the first receipt but no previous receipt was provided
            (_, maybe_prev_receipt, maybe_prev_receipt_proof) => {
                debug!(
                    "Expected two receipts; received one.
                    tx_index_in_block = {:?},
                    maybe_prev_receipt = {:?},
                    maybe_prev_receipt_proof = {:?}",
                    tx_index_in_block,
                    maybe_prev_receipt,
                    maybe_prev_receipt_proof
                );

                return Err(ErrorKind::InvalidTxInfo.into());
            }
        };

        // store
        let address = TransactionIndex {
            block_hash,
            index: tx_index_in_block,
        };

        self.verified
            .write()
            .entry(tx_hash)
            .or_insert(PendingItem::pending())
            .set((tx, receipt, address, prior_gas_used));

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
        &self, io: &dyn NetworkContext, peer: &NodeId, hashes: Vec<H256>,
    ) -> Result<Option<RequestId>, Error> {
        debug!("send_request peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();
        let msg: Box<dyn Message> = Box::new(GetTxInfos { request_id, hashes });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        debug!("tx info sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_TX_INFOS_IN_FLIGHT,
            TX_INFO_REQUEST_BATCH_SIZE,
            |peer, hashes| self.send_request(io, peer, hashes),
        );
    }
}
