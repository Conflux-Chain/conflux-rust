// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    common::{FutureItem, PendingItem, SyncManager, TimeOrdered},
    Witnesses,
};
use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerState, LedgerInfo, Peers},
        error::*,
        message::{msgid, GetTxInfos, TxInfo},
    },
    message::{Message, RequestId},
    verification::{
        is_valid_receipt_inclusion_proof, is_valid_tx_inclusion_proof,
    },
    UniqueId,
};
use cfx_parameters::light::{
    CACHE_TIMEOUT, MAX_TX_INFOS_IN_FLIGHT, TX_INFO_REQUEST_BATCH_SIZE,
    TX_INFO_REQUEST_TIMEOUT,
};
use cfx_types::{H256, U256};
use futures::future::FutureExt;
use lru_time_cache::LruCache;
use network::{node_table::NodeId, NetworkContext};
use parking_lot::RwLock;
use primitives::{
    Receipt, SignedTransaction, TransactionIndex, TransactionStatus,
};
use std::{future::Future, sync::Arc};

#[derive(Debug)]
#[allow(dead_code)]
struct Statistics {
    cached: usize,
    in_flight: usize,
    waiting: usize,
}

// prioritize earlier requests
type MissingTxInfo = TimeOrdered<H256>;

#[derive(Clone)]
pub struct TxInfoValidated {
    pub tx: SignedTransaction,
    pub receipt: Receipt,
    pub tx_index: TransactionIndex,
    pub prior_gas_used: U256,
}

type PendingTxInfo = PendingItem<TxInfoValidated, ClonableError>;

pub struct TxInfos {
    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingTxInfo>,

    // block txs received from full node
    verified: Arc<RwLock<LruCache<H256, PendingTxInfo>>>,

    // witness sync manager
    pub witnesses: Arc<Witnesses>,
}

impl TxInfos {
    pub fn new(
        consensus: SharedConsensusGraph, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>, witnesses: Arc<Witnesses>,
    ) -> Self {
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
    pub fn print_stats(&self) {
        debug!(
            "tx info sync statistics: {:?}",
            Statistics {
                cached: self.verified.read().len(),
                in_flight: self.sync_manager.num_in_flight(),
                waiting: self.sync_manager.num_waiting(),
            }
        );
    }

    #[inline]
    pub fn request_now(
        &self, io: &dyn NetworkContext, hash: H256,
    ) -> impl Future<Output = Result<TxInfoValidated>> {
        let mut verified = self.verified.write();

        if !verified.contains_key(&hash) {
            let missing = std::iter::once(MissingTxInfo::new(hash));

            self.sync_manager.request_now(missing, |peer, hashes| {
                self.send_request(io, peer, hashes)
            });
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
        infos: impl Iterator<Item = TxInfo>,
    ) -> Result<()> {
        for info in infos {
            trace!("Validating tx_info {:?}", info);

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
    fn validate_and_store(&self, info: TxInfo) -> Result<()> {
        let tx_hash = info.tx.hash();

        // validate bloom
        if let Err(e) = self.validate_and_store_tx_info(info) {
            // forward error to both rpc caller(s) and sync handler
            // so we need to make it clonable
            let e = ClonableError::from(e);

            self.verified
                .write()
                .entry(tx_hash)
                .or_insert(PendingItem::pending())
                .set_error(e.clone());

            bail!(e);
        }

        Ok(())
    }

    #[inline]
    fn validate_and_store_tx_info(&self, info: TxInfo) -> Result<()> {
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
            bail!(Error::InvalidTxInfo {
                reason: format!(
                    "Inconsisent block index: {} >= {}",
                    block_index_in_epoch, num_blocks_in_epoch
                )
            });
        }

        if tx_index_in_block >= num_txs_in_block {
            bail!(Error::InvalidTxInfo {
                reason: format!(
                    "Inconsisent tx index: {} >= {}",
                    tx_index_in_block, num_txs_in_block
                )
            });
        }

        // only executed instances of the transaction are acceptable;
        // receipts belonging to non-executed instances should not be sent
        if receipt.outcome_status != TransactionStatus::Success
            && receipt.outcome_status != TransactionStatus::Failure
        {
            bail!(Error::InvalidTxInfo {
                reason: format!(
                    "Unexpected outcome status in tx info: {:?}",
                    receipt.outcome_status
                )
            });
        }

        let block_hash = match self.ledger.block_hashes_in(epoch)? {
            hs if hs.len() != num_blocks_in_epoch => {
                bail!(Error::InvalidTxInfo {
                    reason: format!(
                        "Number of blocks in epoch mismatch: local = {}, received = {}",
                        hs.len(), num_blocks_in_epoch),
                });
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
            bail!(Error::InvalidTxInfo {
                reason: "Transaction proof verification failed".to_owned()
            });
        }

        // verify receipt proof
        let verified_epoch_receipts_root =
            self.witnesses.root_hashes_of(epoch)?.receipts_root_hash;

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
            bail!(Error::InvalidTxInfo {
                reason: "Receipt proof verification failed".to_owned()
            });
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
                    bail!(Error::InvalidTxInfo {
                        reason: "Previous receipt proof verification failed"
                            .to_owned()
                    });
                }

                prev_receipt.accumulated_gas_used
            }

            // not the first receipt but no previous receipt was provided
            (_, maybe_prev_receipt, maybe_prev_receipt_proof) => {
                bail!(Error::InvalidTxInfo {
                    reason: format!(
                        "Expected two receipts; received one.
                        tx_index_in_block = {:?},
                        maybe_prev_receipt = {:?},
                        maybe_prev_receipt_proof = {:?}",
                        tx_index_in_block,
                        maybe_prev_receipt,
                        maybe_prev_receipt_proof
                    )
                });
            }
        };

        // store
        let tx_index = TransactionIndex {
            block_hash,
            real_index: tx_index_in_block,
            is_phantom: false,
            rpc_index: None,
        };

        self.verified
            .write()
            .entry(tx_hash)
            .or_insert(PendingItem::pending())
            .set(TxInfoValidated {
                tx,
                receipt,
                tx_index,
                prior_gas_used,
            });

        Ok(())
    }

    #[inline]
    pub fn clean_up(&self) {
        // remove timeout in-flight requests
        let timeout = *TX_INFO_REQUEST_TIMEOUT;
        let infos = self.sync_manager.remove_timeout_requests(timeout);
        trace!("Timeout tx-infos ({}): {:?}", infos.len(), infos);
        self.sync_manager.insert_waiting(infos.into_iter());

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
            "send_request GetTxInfos peer={:?} id={:?} hashes={:?}",
            peer,
            request_id,
            hashes
        );

        let msg: Box<dyn Message> = Box::new(GetTxInfos { request_id, hashes });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    pub fn sync(&self, io: &dyn NetworkContext) {
        self.sync_manager.sync(
            MAX_TX_INFOS_IN_FLIGHT,
            TX_INFO_REQUEST_BATCH_SIZE,
            |peer, hashes| self.send_request(io, peer, hashes),
        );
    }
}
