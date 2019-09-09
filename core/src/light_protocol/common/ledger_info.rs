// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_types::{Bloom, H256};
use primitives::{
    Block, BlockHeader, BlockHeaderBuilder, EpochNumber, Receipt, StateRoot,
};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        message::{StateRootWithProof, WitnessInfoWithHeight},
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

/// NOTE: we use `height` when we talk about headers on the pivot chain
///       we use `epoch` when we talk about execution results
///
/// example: the roots of epoch=5 are stored in the header at height=10
///          (or later, if there is blaming involved)
impl LedgerInfo {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        LedgerInfo { consensus }
    }

    /// Get block `hash`, if it exists.
    #[inline]
    pub fn block(&self, hash: H256) -> Result<Block, Error> {
        self.consensus
            .data_man
            .block_by_hash(&hash, false /* update_cache */)
            .map(|b| (*b).clone())
            .ok_or(ErrorKind::InternalError.into())
    }

    /// Get header `hash`, if it exists.
    #[inline]
    pub fn header(&self, hash: H256) -> Result<BlockHeader, Error> {
        self.consensus
            .data_man
            .block_header_by_hash(&hash)
            .map(|h| (*h).clone())
            .ok_or(ErrorKind::InternalError.into())
    }

    /// Get hash of block at `height` on the pivot chain, if it exists.
    #[inline]
    pub fn pivot_hash_of(&self, height: u64) -> Result<H256, Error> {
        let epoch = EpochNumber::Number(height);
        Ok(self.consensus.get_hash_from_epoch_number(epoch)?)
    }

    /// Get header at `height` on the pivot chain, if it exists.
    #[inline]
    pub fn pivot_header_of(&self, height: u64) -> Result<BlockHeader, Error> {
        let pivot = self.pivot_hash_of(height)?;
        self.header(pivot)
    }

    /// Get all block hashes corresponding to the pivot block at `height`.
    /// The hashes are returned in the deterministic execution order.
    #[inline]
    pub fn block_hashes_in(&self, height: u64) -> Result<Vec<H256>, Error> {
        let epoch = EpochNumber::Number(height);
        Ok(self.consensus.get_block_hashes_by_epoch(epoch)?)
    }

    /// Get the correct deferred state root of the block at `height` on the
    /// pivot chain based on local execution information.
    #[inline]
    pub fn correct_deferred_state_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let root = self.state_root_of(epoch)?;
        Ok(root.compute_state_root_hash())
    }

    /// Get the correct deferred receipts root of the block at `height` on the
    /// pivot chain based on local execution information.
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

    /// Get the correct deferred logs bloom root of the block at `height` on the
    /// pivot chain based on local execution information.
    #[inline]
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

    /// Get the state trie corresponding to the execution of `epoch`.
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

    /// Get the state trie roots corresponding to the execution of `epoch`.
    #[inline]
    pub fn state_root_of(&self, epoch: u64) -> Result<StateRoot, Error> {
        match self.state_of(epoch)?.get_state_root() {
            Ok(Some(root)) => Ok(root.state_root),
            _ => Err(ErrorKind::InternalError.into()),
        }
    }

    /// Get the state trie roots corresponding to the execution of `epoch`.
    /// Returns a ledger proof along with the state trie roots.
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

    /// Get the state trie entry under `key` at `epoch`.
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

    /// Get the epoch receipts corresponding to the execution of `epoch`.
    /// Returns a vector of receipts for each block in `epoch`.
    #[inline]
    pub fn receipts_of(&self, epoch: u64) -> Result<Vec<Vec<Receipt>>, Error> {
        let pivot = self.pivot_hash_of(epoch)?;
        let hashes = self.block_hashes_in(epoch)?;

        hashes
            .into_iter()
            .map(|h| {
                self.consensus
                    .data_man
                    .block_execution_result_by_hash_with_epoch(
                        &h, &pivot, false, /* update_cache */
                    )
                    .map(|res| (*res.receipts).clone())
                    .ok_or(ErrorKind::InternalError.into())
            })
            .collect()
    }

    /// Get the aggregated bloom corresponding to the execution of `epoch`.
    #[inline]
    pub fn bloom_of(&self, epoch: u64) -> Result<Bloom, Error> {
        let pivot = self.pivot_hash_of(epoch)?;
        let hashes = self.block_hashes_in(epoch)?;

        let blooms = hashes
            .into_iter()
            .map(|h| {
                self.consensus
                    .data_man
                    .block_execution_result_by_hash_with_epoch(
                        &h, &pivot, false, /* update_cache */
                    )
                    .map(|res| res.bloom)
                    .ok_or(ErrorKind::InternalError.into())
            })
            .collect::<Result<Vec<Bloom>, Error>>()?;

        Ok(BlockHeaderBuilder::compute_aggregated_bloom(blooms))
    }

    /// Get the witness height that can be used to retrieve the correct header
    /// information of the pivot block at `height`.
    #[inline]
    pub fn witness_of_header_at(&self, height: u64) -> Option<u64> {
        self.consensus.first_trusted_header_starting_from(height)
    }

    /// Get the witness height that can be used to retrieve the correct header
    /// information corresponding to the execution of `epoch`.
    #[inline]
    pub fn witness_of_state_at(&self, epoch: u64) -> Option<u64> {
        let height = epoch + DEFERRED_STATE_EPOCH_COUNT;
        self.consensus.first_trusted_header_starting_from(height)
    }

    /// Get a list of header heights required to verify the roots at `epoch`
    /// based on the blame information.
    #[inline]
    pub fn headers_needed_to_verify(
        &self, epoch: u64,
    ) -> Result<Vec<u64>, Error> {
        // find the first header that can verify the state root requested
        let witness = match self.witness_of_state_at(epoch) {
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

        self.headers_seen_by_witness(witness)
    }

    /// Get a list of all headers for which the block at height `witness` on the
    /// pivot chain stores the correct roots based on the blame information.
    /// NOTE: This list will contains `witness` in all cases.
    #[inline]
    pub fn headers_seen_by_witness(
        &self, witness: u64,
    ) -> Result<Vec<u64>, Error> {
        let blame = self.pivot_header_of(witness)?.blame() as u64;

        // assumption: the witness header is correct
        // i.e. it does not blame blocks at or before the genesis block
        assert!(witness > blame);

        // collect all header heights that were used to compute DSR of `witness`
        Ok((0..(blame + 1)).map(|ii| witness - ii).collect())
    }

    /// Get a list of all correct receipts roots stored in the header at
    /// height `witness` on the pivot chain.
    #[inline]
    pub fn receipts_roots_seen_by_witness(
        &self, witness: u64,
    ) -> Result<Vec<H256>, Error> {
        self.headers_seen_by_witness(witness)?
            .into_iter()
            .map(|height| self.correct_deferred_receipts_root_hash_of(height))
            .collect()
    }

    /// Get a list of all correct log bloom hashes stored in the header at
    /// height `witness` on the pivot chain.
    #[inline]
    pub fn bloom_hashes_seen_by_witness(
        &self, witness: u64,
    ) -> Result<Vec<H256>, Error> {
        self.headers_seen_by_witness(witness)?
            .into_iter()
            .map(|height| self.correct_deferred_logs_root_hash_of(height))
            .collect()
    }

    /// Get a list of all correct log bloom hashes stored in the header at
    /// height `witness` on the pivot chain.
    #[inline]
    pub fn witness_info(
        &self, witness: u64,
    ) -> Result<WitnessInfoWithHeight, Error> {
        let receipt_hashes = self.receipts_roots_seen_by_witness(witness)?;
        let bloom_hashes = self.bloom_hashes_seen_by_witness(witness)?;

        Ok(WitnessInfoWithHeight {
            height: witness,
            receipt_hashes,
            bloom_hashes,
        })
    }
}
