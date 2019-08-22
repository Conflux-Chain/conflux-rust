// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_types::H256;
use primitives::{BlockHeader, EpochNumber, Receipt, StateRoot};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        message::{ReceiptsWithProof, StateRootWithProof},
        Error, ErrorKind,
    },
    parameters::consensus::DEFERRED_STATE_EPOCH_COUNT,
    statedb::StateDb,
    storage::{
        state::{State, StateTrait},
        state_manager::StateManagerTrait,
        SnapshotAndEpochIdRef, StateProof,
    },
};

pub struct LedgerInfo {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,
}

impl LedgerInfo {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        LedgerInfo { consensus }
    }

    #[inline]
    pub fn pivot_hash_of(&self, epoch: u64) -> Result<H256, Error> {
        let epoch = EpochNumber::Number(epoch);
        Ok(self.consensus.get_hash_from_epoch_number(epoch)?)
    }

    #[inline]
    pub fn pivot_header_of(
        &self, epoch: u64,
    ) -> Result<Arc<BlockHeader>, Error> {
        let pivot = self.pivot_hash_of(epoch)?;
        let header = self.consensus.data_man.block_header_by_hash(&pivot);
        header.ok_or(ErrorKind::InternalError.into())
    }

    #[inline]
    pub fn block_hashes_in(&self, epoch: u64) -> Result<Vec<H256>, Error> {
        let epoch = EpochNumber::Number(epoch);
        Ok(self.consensus.get_block_hashes_by_epoch(epoch)?)
    }

    #[inline]
    pub fn correct_deferred_state_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let root = self.state_root_of(epoch)?;
        Ok(root.compute_state_root_hash())
    }

    #[inline]
    pub fn correct_deferred_receipts_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.pivot_hash_of(epoch)?;

        self.consensus
            .data_man
            .get_epoch_execution_commitments(&pivot)
            .map(|c| c.receipts_root)
            .ok_or(ErrorKind::InternalError.into())
    }

    #[inline]
    #[allow(dead_code)]
    pub fn correct_deferred_logs_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.pivot_hash_of(epoch)?;

        self.consensus
            .data_man
            .get_epoch_execution_commitments(&pivot)
            .map(|c| c.logs_bloom_hash)
            .ok_or(ErrorKind::InternalError.into())
    }

    #[inline]
    pub fn state_of(&self, epoch: u64) -> Result<State, Error> {
        let pivot = self.pivot_hash_of(epoch)?;

        let state = self
            .consensus
            .data_man
            .storage_manager
            .get_state_no_commit(SnapshotAndEpochIdRef::new(&pivot, None));

        match state {
            Ok(Some(state)) => Ok(state),
            _ => Err(ErrorKind::InternalError.into()),
        }
    }

    #[inline]
    pub fn state_root_of(&self, epoch: u64) -> Result<StateRoot, Error> {
        match self.state_of(epoch)?.get_state_root() {
            Ok(Some(root)) => Ok(root.state_root),
            _ => Err(ErrorKind::InternalError.into()),
        }
    }

    #[inline]
    pub fn state_root_with_proof_of(
        &self, epoch: u64,
    ) -> Result<StateRootWithProof, Error> {
        let root = self.state_root_of(epoch)?;

        let proof = self
            .headers_needed_to_verify(epoch)?
            .into_iter()
            .map(|h| self.correct_deferred_state_root_hash_of(h))
            .collect::<Result<Vec<H256>, Error>>()?;

        Ok(StateRootWithProof { root, proof })
    }

    #[inline]
    pub fn state_entry_at(
        &self, epoch: u64, key: &Vec<u8>,
    ) -> Result<(Option<Vec<u8>>, StateProof), Error> {
        let state = self.state_of(epoch)?;

        let (value, proof) = StateDb::new(state)
            .get_raw_with_proof(key)
            .or(Err(ErrorKind::InternalError))?;

        let value = value.map(|x| x.to_vec());
        Ok((value, proof))
    }

    #[inline]
    pub fn epoch_receipts_of(
        &self, epoch: u64,
    ) -> Result<Vec<Vec<Receipt>>, Error> {
        let pivot = self.pivot_hash_of(epoch)?;
        let hashes = self.block_hashes_in(epoch)?;

        hashes
            .into_iter()
            .map(|h| {
                self.consensus
                    .data_man
                    .block_results_by_hash_with_epoch(&h, &pivot, false)
                    .map(|res| (*res.receipts).clone())
                    .ok_or(ErrorKind::InternalError.into())
            })
            .collect()
    }

    #[inline]
    pub fn receipts_with_proof_of(
        &self, epoch: u64,
    ) -> Result<ReceiptsWithProof, Error> {
        let receipts = self.epoch_receipts_of(epoch)?;

        let proof = self
            .headers_needed_to_verify(epoch)?
            .into_iter()
            .map(|h| self.correct_deferred_receipts_root_hash_of(h))
            .collect::<Result<Vec<H256>, Error>>()?;

        Ok(ReceiptsWithProof { receipts, proof })
    }

    #[inline]
    pub fn headers_needed_to_verify(
        &self, epoch: u64,
    ) -> Result<Vec<u64>, Error> {
        // find the first header that can verify the state root requested
        let witness = self.consensus.first_epoch_with_correct_state_of(epoch);

        let witness = match witness {
            Some(epoch) => epoch,
            None => {
                warn!("Unable to produce state proof for epoch {}", epoch);
                return Err(ErrorKind::UnableToProduceProof.into());
            }
        };

        let blame = self.pivot_header_of(witness)?.blame() as u64;

        // assumption: the state root requested can be verified by the witness
        assert!(witness >= epoch + DEFERRED_STATE_EPOCH_COUNT);
        assert!(witness <= epoch + DEFERRED_STATE_EPOCH_COUNT + blame);

        // assumption: the witness header is correct
        // i.e. it does not blame blocks at or before the genesis block
        assert!(witness > blame);

        // collect all header heights that were used to compute DSR of `witness`
        Ok((0..(blame + 1)).map(|ii| witness - ii).collect())
    }
}
