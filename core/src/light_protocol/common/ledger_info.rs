// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{message::WitnessInfoWithHeight, Error, ErrorKind},
};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_parameters::consensus::DEFERRED_STATE_EPOCH_COUNT;
use cfx_statedb::{StateDb, StateDbGetOriginalMethods};
use cfx_storage::{
    state::{State, StateTrait},
    state_manager::StateManagerTrait,
    NodeMerkleProof, StateProof,
};
use cfx_types::{Address, Bloom, H256};
use primitives::{
    Block, BlockHeader, BlockHeaderBuilder, BlockReceipts, EpochNumber,
    StorageKey, StorageRoot,
};

pub struct LedgerInfo {
    // shared consensus graph
    consensus: SharedConsensusGraph,
}

/// NOTE: we use `height` when we talk about headers on the pivot chain
///       we use `epoch` when we talk about execution results
///
/// example: the roots of epoch=5 are stored in the header at height=10
///          (or later, if there is blaming involved)
impl LedgerInfo {
    pub fn new(consensus: SharedConsensusGraph) -> Self {
        LedgerInfo { consensus }
    }

    /// Get block `hash`, if it exists.
    #[inline]
    pub fn block(&self, hash: H256) -> Result<Block, Error> {
        self.consensus
            .get_data_manager()
            .block_by_hash(&hash, false /* update_cache */)
            .map(|b| (*b).clone())
            .ok_or_else(|| {
                ErrorKind::InternalError(format!("Block {:?} not found", hash))
                    .into()
            })
    }

    /// Get header `hash`, if it exists.
    #[inline]
    pub fn header(&self, hash: H256) -> Result<BlockHeader, Error> {
        self.consensus
            .get_data_manager()
            .block_header_by_hash(&hash)
            .map(|h| (*h).clone())
            .ok_or_else(|| {
                ErrorKind::InternalError(format!("Header {:?} not found", hash))
                    .into()
            })
    }

    /// Get hash of block at `height` on the pivot chain, if it exists.
    #[inline]
    fn pivot_hash_of(&self, height: u64) -> Result<H256, Error> {
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
    fn correct_deferred_state_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.pivot_hash_of(epoch)?;

        let commitments = self
            .consensus
            .get_data_manager()
            .get_epoch_execution_commitment_with_db(&pivot)
            .ok_or_else(|| {
                Error::from(ErrorKind::InternalError(format!(
                    "Execution commitments for {:?} not found",
                    pivot
                )))
            })?;

        Ok(commitments
            .state_root_with_aux_info
            .state_root
            .compute_state_root_hash())
    }

    /// Get the correct deferred receipts root of the block at `height` on the
    /// pivot chain based on local execution information.
    #[inline]
    fn correct_deferred_receipts_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.pivot_hash_of(epoch)?;

        let commitments = self
            .consensus
            .get_data_manager()
            .get_epoch_execution_commitment_with_db(&pivot)
            .ok_or_else(|| {
                Error::from(ErrorKind::InternalError(format!(
                    "Execution commitments for {:?} not found",
                    pivot
                )))
            })?;

        Ok(commitments.receipts_root)
    }

    /// Get the correct deferred logs bloom root of the block at `height` on the
    /// pivot chain based on local execution information.
    #[inline]
    fn correct_deferred_logs_root_hash_of(
        &self, height: u64,
    ) -> Result<H256, Error> {
        let epoch = height.saturating_sub(DEFERRED_STATE_EPOCH_COUNT);
        let pivot = self.pivot_hash_of(epoch)?;

        let commitments = self
            .consensus
            .get_data_manager()
            .get_epoch_execution_commitment_with_db(&pivot)
            .ok_or_else(|| {
                Error::from(ErrorKind::InternalError(format!(
                    "Execution commitments for {:?} not found",
                    pivot
                )))
            })?;

        Ok(commitments.logs_bloom_hash)
    }

    /// Get the number of epochs per snapshot period.
    #[inline]
    pub fn snapshot_epoch_count(&self) -> u32 {
        self.consensus.get_data_manager().get_snapshot_epoch_count()
    }

    /// Get the state trie corresponding to the execution of `epoch`.
    #[inline]
    fn state_of(&self, epoch: u64) -> Result<State, Error> {
        let pivot = self.pivot_hash_of(epoch)?;

        let maybe_state_index = self
            .consensus
            .get_data_manager()
            .get_state_readonly_index(&pivot);
        let state = maybe_state_index.map(|state_index| {
            self.consensus
                .get_data_manager()
                .storage_manager
                .get_state_no_commit(state_index, /* try_open = */ true)
        });

        match state {
            Some(Ok(Some(state))) => Ok(state),
            _ => {
                bail!(ErrorKind::InternalError(format!(
                    "State of epoch {} not found",
                    epoch
                )));
            }
        }
    }

    /// Get the state trie roots corresponding to the execution of `epoch`.
    #[inline]
    pub fn state_root_of(
        &self, epoch: u64,
    ) -> Result<StateRootWithAuxInfo, Error> {
        match self.state_of(epoch)?.get_state_root() {
            Ok(root) => Ok(root),
            Err(e) => {
                bail!(ErrorKind::InternalError(format!(
                    "State root of epoch {} not found: {:?}",
                    epoch, e
                )));
            }
        }
    }

    /// Get the state trie entry under `key` at `epoch`.
    #[inline]
    pub fn state_entry_at(
        &self, epoch: u64, key: &Vec<u8>,
    ) -> Result<(Option<Vec<u8>>, StateProof), Error> {
        let state = self.state_of(epoch)?;

        let (value, proof) = StateDb::new(state)
            .get_original_raw_with_proof(StorageKey::from_key_bytes(&key))?;

        let value = value.map(|x| x.to_vec());
        Ok((value, proof))
    }

    /// Get the storage root of contract `address` at `epoch`.
    #[inline]
    pub fn storage_root_of(
        &self, epoch: u64, address: &Address,
    ) -> Result<(Option<StorageRoot>, NodeMerkleProof), Error> {
        let state = self.state_of(epoch)?;
        Ok(
            StateDb::new(state)
                .get_original_storage_root_with_proof(address)?,
        )
    }

    /// Get the epoch receipts corresponding to the execution of `epoch`.
    /// Returns a vector of receipts for each block in `epoch`.
    #[inline]
    pub fn receipts_of(&self, epoch: u64) -> Result<Vec<BlockReceipts>, Error> {
        if epoch == 0 {
            return Ok(vec![]);
        }

        let pivot = self.pivot_hash_of(epoch)?;
        let hashes = self.block_hashes_in(epoch)?;

        hashes
            .into_iter()
            .map(|h| {
                self.consensus
                    .get_data_manager()
                    .block_execution_result_by_hash_with_epoch(
                        &h, &pivot, false, /* update_pivot_assumption */
                        false, /* update_cache */
                    )
                    .map(|res| (*res.block_receipts).clone())
                    .ok_or_else(|| {
                        ErrorKind::InternalError(format!(
                            "Receipts of epoch {} not found",
                            epoch
                        ))
                        .into()
                    })
            })
            .collect()
    }

    /// Get the aggregated bloom corresponding to the execution of `epoch`.
    #[inline]
    pub fn bloom_of(&self, epoch: u64) -> Result<Bloom, Error> {
        if epoch == 0 {
            return Ok(Bloom::zero());
        }

        let pivot = self.pivot_hash_of(epoch)?;
        let hashes = self.block_hashes_in(epoch)?;

        let blooms = hashes
            .into_iter()
            .map(|h| {
                self.consensus
                    .get_data_manager()
                    .block_execution_result_by_hash_with_epoch(
                        &h, &pivot, false, /* update_pivot_assumption */
                        false, /* update_cache */
                    )
                    .map(|res| res.bloom)
                    .ok_or_else(|| {
                        ErrorKind::InternalError(format!(
                            "Logs bloom of epoch {} not found",
                            epoch
                        ))
                        .into()
                    })
            })
            .collect::<Result<Vec<Bloom>, Error>>()?;

        Ok(BlockHeaderBuilder::compute_aggregated_bloom(blooms))
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

    /// Get all correct state roots, receipts roots, and bloom hashes seen by
    /// the header at height `witness`.
    #[inline]
    pub fn witness_info(
        &self, witness: u64,
    ) -> Result<WitnessInfoWithHeight, Error> {
        let mut state_root_hashes = vec![];
        let mut receipt_hashes = vec![];
        let mut bloom_hashes = vec![];

        for h in self.headers_seen_by_witness(witness)? {
            state_root_hashes
                .push(self.correct_deferred_state_root_hash_of(h)?);
            receipt_hashes
                .push(self.correct_deferred_receipts_root_hash_of(h)?);
            bloom_hashes.push(self.correct_deferred_logs_root_hash_of(h)?);
        }

        Ok(WitnessInfoWithHeight {
            height: witness,
            state_root_hashes,
            receipt_hashes,
            bloom_hashes,
        })
    }
}
