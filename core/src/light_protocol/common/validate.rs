// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use std::sync::Arc;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{Error, ErrorKind},
    primitives::{Block, SignedTransaction},
};

use super::LedgerInfo;

pub struct Validate {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,
}

impl Validate {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        let ledger = LedgerInfo::new(consensus.clone());
        Validate { consensus, ledger }
    }

    #[inline]
    pub fn genesis_hash(&self, genesis: H256) -> Result<(), Error> {
        match self.consensus.data_man.true_genesis_block.hash() {
            h if h == genesis => Ok(()),
            h => {
                debug!(
                    "Genesis mismatch (ours: {:?}, theirs: {:?})",
                    h, genesis
                );
                Err(ErrorKind::GenesisMismatch.into())
            }
        }
    }

    #[inline]
    pub fn tx_signatures(
        &self, txs: &Vec<SignedTransaction>,
    ) -> Result<(), Error> {
        for tx in txs {
            match tx.verify_public(false /* skip */) {
                Ok(true) => continue,
                _ => {
                    warn!("Tx signature verification failed for {:?}", tx);
                    return Err(ErrorKind::InvalidTxSignature.into());
                }
            }
        }

        Ok(())
    }

    #[inline]
    pub fn block_txs(
        &self, hash: H256, txs: &Vec<SignedTransaction>,
    ) -> Result<(), Error> {
        // first, validate signatures for each tx
        self.tx_signatures(txs)?;

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
