// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Bloom, H256};
use primitives::{
    Block, BlockHeader, BlockHeaderBuilder, BlockReceipts, EpochNumber,
    StateRoot, StorageKey,
};

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{message::WitnessInfoWithHeight, Error, ErrorKind},
    parameters::consensus::DEFERRED_STATE_EPOCH_COUNT,
    statedb::StateDb,
    storage::{
        state::{State, StateTrait},
        state_manager::StateManagerTrait,
        StateProof,
    },
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
            .ok_or(ErrorKind::InternalError.into())
    }

    /// Get header `hash`, if it exists.
    #[inline]
    pub fn header(&self, hash: H256) -> Result<BlockHeader, Error> {
        self.consensus
            .get_data_manager()
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
            .get_data_manager()
            .get_epoch_execution_commitment(&pivot)
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
            .get_data_manager()
            .get_epoch_execution_commitment(&pivot)
            .map(|c| c.logs_bloom_hash)
            .ok_or(ErrorKind::InternalError.into())
    }

    /// Get the state trie corresponding to the execution of `epoch`.
    #[inline]
    pub fn state_of(&self, epoch: u64) -> Result<State, Error> {
        let pivot = self.pivot_hash_of(epoch)?;

        let (_state_index_guard, maybe_state_index) = self
            .consensus
            .get_data_manager()
            .get_state_readonly_index(&pivot)
            .into();
        let state = maybe_state_index.map(|state_index| {
            self.consensus
                .get_data_manager()
                .storage_manager
                .get_state_no_commit(state_index, /* try_open = */ true)
        });

        match state {
            Some(Ok(Some(state))) => Ok(state),
            _ => Err(ErrorKind::InternalError.into()),
        }
    }

    /// Get the state trie roots corresponding to the execution of `epoch`.
    #[inline]
    pub fn state_root_of(&self, epoch: u64) -> Result<StateRoot, Error> {
        match self.state_of(epoch)?.get_state_root() {
            Ok(root) => Ok(root.state_root),
            _ => Err(ErrorKind::InternalError.into()),
        }
    }

    /// Get the state trie entry under `key` at `epoch`.
    #[inline]
    pub fn state_entry_at(
        &self, epoch: u64, key: &Vec<u8>,
    ) -> Result<(Option<Vec<u8>>, StateProof), Error> {
        let state = self.state_of(epoch)?;

        let (value, proof) = StateDb::new(state)
            .get_raw_with_proof(StorageKey::from_key_bytes(&key))
            .or(Err(ErrorKind::InternalError))?;

        let value = value.map(|x| x.to_vec());
        Ok((value, proof))
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
                        &h, &pivot, false, /* update_cache */
                    )
                    .map(|res| (*res.block_receipts).clone())
                    .ok_or(ErrorKind::InternalError.into())
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
        self.consensus.first_trusted_header_starting_from(
            height, None, /* blame_bound */
        )
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
        let mut states = vec![];
        let mut receipts = vec![];
        let mut blooms = vec![];

        for h in self.headers_seen_by_witness(witness)? {
            states.push(self.correct_deferred_state_root_hash_of(h)?);
            receipts.push(self.correct_deferred_receipts_root_hash_of(h)?);
            blooms.push(self.correct_deferred_logs_root_hash_of(h)?);
        }

        Ok(WitnessInfoWithHeight {
            height: witness,
            state_roots: states,
            receipt_hashes: receipts,
            bloom_hashes: blooms,
        })
    }
}
