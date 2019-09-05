// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use cfx_types::H256;
use futures::Future;
use parking_lot::RwLock;
use primitives::SignedTransaction;
use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{Peers, UniqueId, Validate},
        handler::FullPeerState,
        message::{BlockTxsWithHash, GetBlockTxs},
        Error,
    },
    message::Message,
    network::{NetworkContext, PeerId},
    parameters::light::{
        BLOCK_TX_REQUEST_BATCH_SIZE, BLOCK_TX_REQUEST_TIMEOUT_MS,
        MAX_BLOCK_TXS_IN_FLIGHT,
    },
};

use super::{
    future_item::FutureItem, missing_item::TimeOrdered,
    sync_manager::SyncManager,
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
    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // sync and request manager
    sync_manager: SyncManager<H256, MissingBlockTxs>,

    // helper API for validating ledger and state information
    validate: Validate,

    // block txs received from full node
    verified: Arc<RwLock<HashMap<H256, Vec<SignedTransaction>>>>,
}

impl BlockTxs {
    pub(super) fn new(
        consensus: Arc<ConsensusGraph>, peers: Arc<Peers<FullPeerState>>,
        request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let sync_manager = SyncManager::new(peers.clone());
        let validate = Validate::new(consensus.clone());
        let verified = Arc::new(RwLock::new(HashMap::new()));

        BlockTxs {
            request_id_allocator,
            sync_manager,
            validate,
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
    pub(super) fn receive(
        &self, block_txs: impl Iterator<Item = BlockTxsWithHash>,
    ) -> Result<(), Error> {
        for BlockTxsWithHash { hash, block_txs } in block_txs {
            info!("Validating block_txs {:?} with hash {}", block_txs, hash);
            self.validate.block_txs(hash, &block_txs)?;

            self.verified.write().insert(hash, block_txs);
            self.sync_manager.remove_in_flight(&hash);
        }

        Ok(())
    }

    #[inline]
    pub(super) fn clean_up(&self) {
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
    pub(super) fn sync(&self, io: &dyn NetworkContext) {
        info!("block tx sync statistics: {:?}", self.get_statistics());

        self.sync_manager.sync(
            MAX_BLOCK_TXS_IN_FLIGHT,
            BLOCK_TX_REQUEST_BATCH_SIZE,
            |peer, block_hashes| self.send_request(io, peer, block_hashes),
        );
    }
}
