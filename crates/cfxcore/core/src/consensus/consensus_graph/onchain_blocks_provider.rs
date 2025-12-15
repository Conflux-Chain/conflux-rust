use super::ConsensusGraph;

use crate::errors::{invalid_params, Result as CoreResult};
use cfxcore_errors::ProviderBlockError;

use cfx_parameters::consensus::*;

use cfx_types::H256;

use primitives::{compute_block_number, BlockHashOrEpochNumber, EpochNumber};
use std::cmp::min;

impl ConsensusGraph {
    /// Returns the total number of blocks processed in consensus graph.
    ///
    /// This function should only be used in tests.
    /// If the process crashes and recovered, the blocks in the anticone of the
    /// current checkpoint may not be counted since they will not be
    /// inserted into consensus in the recover process.
    pub fn block_count(&self) -> u64 {
        self.inner.read_recursive().total_processed_block_count()
    }

    /// Convert EpochNumber to height based on the current ConsensusGraph
    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, ProviderBlockError> {
        Ok(match epoch_number {
            EpochNumber::Earliest => 0,
            EpochNumber::LatestCheckpoint => {
                self.latest_checkpoint_epoch_number()
            }
            EpochNumber::LatestConfirmed => {
                self.latest_confirmed_epoch_number()
            }
            EpochNumber::LatestMined => self.best_epoch_number(),
            EpochNumber::LatestFinalized => {
                self.latest_finalized_epoch_number()
            }
            EpochNumber::LatestState => self.best_executed_state_epoch_number(),
            EpochNumber::Number(num) => {
                let epoch_num = num;
                if epoch_num > self.inner.read_recursive().best_epoch_number() {
                    return Err(ProviderBlockError::EpochNumberTooLarge);
                }
                epoch_num
            }
        })
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        // try to get from memory
        if let Some(e) =
            self.inner.read_recursive().get_block_epoch_number(hash)
        {
            return Some(e);
        }

        // try to get from db
        self.data_man.block_epoch_number(hash)
    }

    pub fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, ProviderBlockError> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner.read_recursive().block_hashes_by_epoch(height)
            })
    }

    pub fn get_block_hashes_by_epoch_or_block_hash(
        &self, block_hash_or_epoch: BlockHashOrEpochNumber,
    ) -> Result<Vec<H256>, ProviderBlockError> {
        let hashes = match block_hash_or_epoch {
            BlockHashOrEpochNumber::EpochNumber(e) => {
                self.get_block_hashes_by_epoch(e)?
            }
            BlockHashOrEpochNumber::BlockHashWithOption {
                hash: h,
                require_pivot,
            } => {
                // verify the block header exists
                let _ = self
                    .data_manager()
                    .block_header_by_hash(&h)
                    .ok_or("block not found")?;

                let e =
                    self.get_block_epoch_number(&h).ok_or("block not found")?;

                let hashes = self.get_block_hashes_by_epoch(e.into())?;

                // if the provided hash is not the pivot hash,
                // and require_pivot is true or None(default to true)
                // abort
                let pivot_hash = *hashes.last().ok_or("inconsistent state")?;

                if require_pivot.unwrap_or(true) && (h != pivot_hash) {
                    bail!(ProviderBlockError::Common(
                        "require_pivot check failed".into()
                    ));
                }

                hashes
            }
        };
        Ok(hashes)
    }

    /// Get the pivot block hash of the specified epoch number
    pub fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, ProviderBlockError> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner.read().get_pivot_hash_from_epoch_number(height)
            })
    }

    pub fn get_skipped_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, ProviderBlockError> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner
                    .read_recursive()
                    .skipped_block_hashes_by_epoch(height)
            })
    }

    pub fn get_block_epoch_number_with_pivot_check(
        &self, hash: &H256, require_pivot: bool,
    ) -> CoreResult<u64> {
        let inner = &*self.inner.read();
        // TODO: block not found error
        let epoch_number =
            inner.get_block_epoch_number(&hash).ok_or(invalid_params(
                "epoch parameter",
                format!("block's epoch number is not found: {:?}", hash),
            ))?;

        if require_pivot {
            if let Err(..) =
                inner.check_block_pivot_assumption(&hash, epoch_number)
            {
                bail!(invalid_params(
                    "epoch parameter",
                    format!(
                        "should receive a pivot block hash, receives: {:?}",
                        hash
                    ),
                ))
            }
        }
        Ok(epoch_number)
    }

    pub fn get_block_number(
        &self, block_hash: &H256,
    ) -> Result<Option<u64>, String> {
        let inner = self.inner.read_recursive();

        let epoch_number = match inner
            .get_block_epoch_number(block_hash)
            .or_else(|| self.data_man.block_epoch_number(&block_hash))
        {
            None => return Ok(None),
            Some(epoch_number) => epoch_number,
        };

        let blocks = match self
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch_number))
            .ok()
            .or_else(|| {
                self.data_man
                    .executed_epoch_set_hashes_from_db(epoch_number)
            }) {
            None => return Ok(None),
            Some(hashes) => hashes,
        };

        let epoch_hash = blocks.last().expect("Epoch not empty");

        let start_block_number =
            match self.data_man.get_epoch_execution_context(&epoch_hash) {
                None => return Ok(None),
                Some(ctx) => ctx.start_block_number,
            };

        let index_of_block = match blocks.iter().position(|x| x == block_hash) {
            None => return Ok(None),
            Some(index) => index as u64,
        };

        return Ok(Some(compute_block_number(
            start_block_number,
            index_of_block,
        )));
    }

    pub fn validate_stated_epoch(
        &self, epoch_number: &EpochNumber,
    ) -> Result<(), String> {
        match epoch_number {
            EpochNumber::LatestMined => {
                return Err("Latest mined epoch is not executed".into());
            }
            EpochNumber::Number(num) => {
                let latest_state_epoch =
                    self.best_executed_state_epoch_number();
                if *num > latest_state_epoch {
                    return Err(format!("Specified epoch {} is not executed, the latest state epoch is {}", num, latest_state_epoch));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Returns the latest epoch whose state can be exposed safely, which means
    /// its state is available and it's not only visible to optimistic
    /// execution.
    pub fn best_executed_state_epoch_number(&self) -> u64 {
        let state_upper_bound =
            self.data_man.state_availability_boundary.read().upper_bound;
        // Here we can also get `best_state_epoch` from `inner`, but that
        // would acquire the inner read lock.
        let best_epoch_number = self.best_info.read().best_epoch_number;
        let deferred_state_height =
            if best_epoch_number < DEFERRED_STATE_EPOCH_COUNT {
                0
            } else {
                best_epoch_number - DEFERRED_STATE_EPOCH_COUNT + 1
            };
        // state upper bound can be lower than deferred_state_height because
        // the execution is async. It can also be higher
        // because of optimistic execution. Here we guarantee
        // to return an available state without exposing optimistically
        // executed states.
        min(state_upper_bound, deferred_state_height)
    }
}
