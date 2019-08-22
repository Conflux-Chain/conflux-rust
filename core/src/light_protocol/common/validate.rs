// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_types::H256;
use primitives::{BlockHeaderBuilder, SignedTransaction};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        message::{ReceiptsWithProof, StateRootWithProof},
        Error, ErrorKind,
    },
    parameters::consensus::DEFERRED_STATE_EPOCH_COUNT,
};

use super::{LedgerInfo, LedgerProof};

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

    // When validating a ledger proof, we first find the witness - the block
    // header that can be used to verify the the provided hashes against the
    // corresponding on-ledger root hash. The witness is chosen based on the
    // blame field. The root hash can be one of a) deferred state root hash,
    // b) deferred receipts root hash, c) deferred logs bloom hash. Then, we
    // compute the deferred root using the hashes provided and compare it to
    // the hash stored in the witness header.
    #[inline]
    pub fn ledger_proof(
        &self, epoch: u64, proof: LedgerProof,
    ) -> Result<H256, Error> {
        // find the first header that can verify the state root requested
        let witness = self.consensus.first_epoch_with_correct_state_of(epoch);

        let witness = match witness {
            Some(epoch) => epoch,
            None => {
                warn!("Unable to verify state proof for epoch {}", epoch);
                return Err(ErrorKind::UnableToProduceProof.into());
            }
        };

        let witness_header = self.ledger.pivot_header_of(witness)?;
        let blame = witness_header.blame() as u64;

        // assumption: the target state root can be verified by the witness
        assert!(witness >= epoch + DEFERRED_STATE_EPOCH_COUNT);
        assert!(witness <= epoch + DEFERRED_STATE_EPOCH_COUNT + blame);

        // assumption: the witness header is correct
        // i.e. it does not blame blocks at or before the genesis block
        assert!(witness > blame);

        // do the actual validation
        proof.validate(witness_header)?;

        // return the root hash corresponding to `epoch`
        let index = (witness - epoch - DEFERRED_STATE_EPOCH_COUNT) as usize;
        let received_root_hash = proof[index];

        Ok(received_root_hash)
    }

    #[inline]
    pub fn pivot_hash(&self, epoch: u64, hash: H256) -> Result<(), Error> {
        match self.ledger.pivot_hash_of(epoch)? {
            h if h == hash => Ok(()),
            h => {
                // NOTE: this can happen in normal scenarios
                // where the pivot chain has not converged
                debug!("Pivot hash mismatch: local={}, response={}", h, hash);
                Err(ErrorKind::PivotHashMismatch.into())
            }
        }
    }

    #[inline]
    pub fn receipts(
        &self, epoch: u64, rwp: &ReceiptsWithProof,
    ) -> Result<(), Error> {
        let ReceiptsWithProof { receipts, proof } = rwp;
        let proof = LedgerProof::ReceiptsRoot(proof.to_vec());

        // convert Vec<Vec<_>> to Vec<Arc<Vec<_>>>
        let rs = receipts.into_iter().cloned().map(Arc::new).collect();

        let received = self.ledger_proof(epoch, proof)?;
        let computed = BlockHeaderBuilder::compute_block_receipts_root(&rs);

        if received != computed {
            info!(
                "Receipts root hash mismatch: received={}, computed={}",
                received, computed
            );
            return Err(ErrorKind::InvalidReceipts.into());
        }

        Ok(())
    }

    #[inline]
    pub fn state_root(
        &self, epoch: u64, srwp: &StateRootWithProof,
    ) -> Result<(), Error> {
        let StateRootWithProof { root, proof } = srwp;
        let proof = LedgerProof::StateRoot(proof.to_vec());

        let received = self.ledger_proof(epoch, proof)?;
        let computed = root.compute_state_root_hash();

        if received != computed {
            info!(
                "State root hash mismatch: received={}, computed={}",
                received, computed
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        Ok(())
    }

    #[inline]
    pub fn txs(&self, txs: &Vec<SignedTransaction>) -> Result<(), Error> {
        for tx in txs {
            match tx.verify_public(false) {
                Ok(true) => continue,
                _ => {
                    warn!("Tx signature verification failed for {:?}", tx);
                    return Err(ErrorKind::InvalidTxSignature.into());
                }
            }
        }

        Ok(())
    }
}
