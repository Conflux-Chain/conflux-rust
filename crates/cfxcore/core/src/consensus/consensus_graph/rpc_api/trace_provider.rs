pub use crate::consensus::{
    consensus_inner::{ConsensusGraphInner, ConsensusInnerConfig},
    consensus_trait::SharedConsensusGraph,
};
use crate::{
    block_data_manager::{
        BlockDataManager, BlockExecutionResultWithEpoch, DataVersionTuple,
    },
    consensus::{
        consensus_inner::{
            consensus_executor::ConsensusExecutionConfiguration, StateBlameInfo,
        },
        pos_handler::PosVerifier,
    },
    errors::{invalid_params, invalid_params_check, Result as CoreResult},
    pow::{PowComputer, ProofOfWorkConfig},
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    verification::VerificationConfig,
    NodeType, Notifications,
};
use cfx_execute_helper::{
    estimation::{EstimateExt, EstimateRequest},
    exec_tracer::{
        recover_phantom_traces, ActionType, BlockExecTraces, LocalizedTrace,
        TraceFilter,
    },
    phantom_tx::build_bloom_and_recover_phantom,
};
use cfx_executor::{
    executive::ExecutionOutcome, spec::CommonParams, state::State,
};
use cfx_rpc_eth_types::EvmOverrides;
use geth_tracer::GethTraceWithHash;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use cfx_internal_common::ChainIdParams;
use cfx_parameters::{
    consensus::*,
    consensus_internal::REWARD_EPOCH_COUNT,
    rpc::{
        GAS_PRICE_BLOCK_SAMPLE_SIZE, GAS_PRICE_DEFAULT_VALUE,
        GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
    },
};
use cfx_rpc_cfx_types::PhantomBlock;
use cfx_statedb::StateDb;
use cfx_storage::{
    state::StateTrait, state_manager::StateManagerTrait, StorageState,
};
use cfx_types::{AddressWithSpace, AllChainID, Bloom, Space, H256, U256};
use either::Either;
use itertools::Itertools;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    compute_block_number,
    epoch::BlockHashOrEpochNumber,
    filter::{FilterError, LogFilter},
    log_entry::LocalizedLogEntry,
    pos::PosBlockId,
    receipt::Receipt,
    Block, EpochId, EpochNumber, SignedTransaction, TransactionIndex,
    TransactionStatus,
};
use rayon::prelude::*;
use std::{
    cmp::{max, min},
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};


use super::super::ConsensusGraph;

impl ConsensusGraph {
    /// Get the average gas price of the last GAS_PRICE_TRANSACTION_SAMPLE_SIZE
    /// blocks
    pub fn gas_price(&self, space: Space) -> Option<U256> {
        let inner = self.inner.read();
        let mut last_epoch_number = inner.best_epoch_number();
        let (
            number_of_tx_to_sample,
            mut number_of_blocks_to_sample,
            block_gas_ratio,
        ) = (
            GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
            GAS_PRICE_BLOCK_SAMPLE_SIZE,
            1,
        );
        let mut prices = Vec::new();
        let mut total_block_gas_limit: u64 = 0;
        let mut total_tx_gas_limit: u64 = 0;

        loop {
            if number_of_blocks_to_sample == 0 || last_epoch_number == 0 {
                break;
            }
            if prices.len() == number_of_tx_to_sample {
                break;
            }
            let mut hashes = inner
                .block_hashes_by_epoch(last_epoch_number.into())
                .unwrap();
            hashes.reverse();
            last_epoch_number -= 1;

            for hash in hashes {
                let block = self
                    .data_man
                    .block_by_hash(&hash, false /* update_cache */)
                    .unwrap();
                total_block_gas_limit +=
                    block.block_header.gas_limit().as_u64() * block_gas_ratio;
                for tx in block.transactions.iter() {
                    if space == Space::Native && tx.space() != Space::Native {
                        // For cfx_gasPrice, we only count Native transactions.
                        continue;
                    }
                    // add the tx.gas() to total_tx_gas_limit even it is packed
                    // multiple times because these tx all
                    // will occupy block's gas space
                    total_tx_gas_limit += tx.transaction.gas().as_u64();
                    prices.push(tx.gas_price().clone());
                    if prices.len() == number_of_tx_to_sample {
                        break;
                    }
                }
                number_of_blocks_to_sample -= 1;
                if number_of_blocks_to_sample == 0
                    || prices.len() == number_of_tx_to_sample
                {
                    break;
                }
            }
        }

        prices.sort();
        if prices.is_empty() || total_tx_gas_limit == 0 {
            Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
        } else {
            let average_gas_limit_multiple =
                total_block_gas_limit / total_tx_gas_limit;
            if average_gas_limit_multiple > 5 {
                // used less than 20%
                Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
            } else if average_gas_limit_multiple >= 2 {
                // used less than 50%
                Some(prices[prices.len() / 8])
            } else {
                // used more than 50%
                Some(prices[prices.len() / 2])
            }
        }
    }

    // TODO: maybe return error for reserved address? Not sure where is the best
    //  place to do the check.
    pub fn next_nonce(
        &self, address: AddressWithSpace,
        block_hash_or_epoch_number: BlockHashOrEpochNumber,
        rpc_param_name: &str,
    ) -> CoreResult<U256> {
        let epoch_number = match block_hash_or_epoch_number {
            BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            } => EpochNumber::Number(
                self.get_block_epoch_number_with_pivot_check(
                    &hash,
                    require_pivot.unwrap_or(true),
                )?,
            ),
            BlockHashOrEpochNumber::EpochNumber(epoch_number) => epoch_number,
        };
        let state = State::new(
            self.get_state_db_by_epoch_number(epoch_number, rpc_param_name)?,
        )?;

        Ok(state.nonce(&address)?)
    }

    fn earliest_epoch_for_trace_filter(&self) -> u64 {
        self.data_man.earliest_epoch_with_trace()
    }

    fn filter_block_receipts<'a>(
        &self, filter: &'a LogFilter, epoch_number: u64, block_hash: H256,
        mut receipts: Vec<Receipt>, mut tx_hashes: Vec<H256>,
    ) -> impl Iterator<Item = LocalizedLogEntry> + 'a {
        // sanity check
        if receipts.len() != tx_hashes.len() {
            warn!("Block ({}) has different number of receipts ({}) to transactions ({}). Database corrupt?", block_hash, receipts.len(), tx_hashes.len());
            assert!(false);
        }

        // iterate in reverse
        receipts.reverse();
        tx_hashes.reverse();

        let mut log_index = receipts
            .iter()
            .flat_map(|r| r.logs.iter())
            .filter(|l| l.space == filter.space)
            .count();

        let receipts_len = receipts.len();

        receipts
            .into_iter()
            .map(|receipt| receipt.logs)
            .zip(tx_hashes)
            .enumerate()
            .flat_map(move |(index, (logs, transaction_hash))| {
                let mut logs: Vec<_> = logs
                    .into_iter()
                    .filter(|l| l.space == filter.space)
                    .collect();

                let current_log_index = log_index;
                let no_of_logs = logs.len();
                log_index -= no_of_logs;

                logs.reverse();
                logs.into_iter().enumerate().map(move |(i, log)| {
                    LocalizedLogEntry {
                        entry: log,
                        block_hash,
                        epoch_number,
                        transaction_hash,
                        // iterating in reverse order
                        transaction_index: receipts_len - index - 1,
                        transaction_log_index: no_of_logs - i - 1,
                        log_index: current_log_index - i - 1,
                    }
                })
            })
            .filter(move |log_entry| filter.matches(&log_entry.entry))
    }

    fn filter_block<'a>(
        &self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64, pivot_hash: H256, block_hash: H256,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry> + 'a, FilterError> {
        // special case for genesis (for now, genesis has no logs)
        if epoch == 0 {
            return Ok(Either::Left(std::iter::empty()));
        }

        // check if epoch is still available
        let min = self.earliest_epoch_for_log_filter();

        if epoch < min {
            return Err(FilterError::EpochAlreadyPruned { epoch, min });
        }

        // get block bloom and receipts from db
        let (block_bloom, receipts) = match self
            .data_man
            .block_execution_result_by_hash_with_epoch(
                &block_hash,
                &pivot_hash,
                false, /* update_pivot_assumption */
                false, /* update_cache */
            ) {
            Some(r) => (r.bloom, r.block_receipts.receipts.clone()),
            None => {
                // `block_hash` must exist so the block not executed yet
                return Err(FilterError::BlockNotExecutedYet { block_hash });
            }
        };

        // filter block
        if !bloom_possibilities
            .iter()
            .any(|bloom| block_bloom.contains_bloom(bloom))
        {
            return Ok(Either::Left(std::iter::empty()));
        }

        // get block body from db
        let block = match self.data_man.block_by_hash(&block_hash, false) {
            Some(b) => b,
            None => {
                // `block_hash` must exist so this is an internal error
                error!(
                    "Block {:?} in epoch {} ({:?}) not found",
                    block_hash, epoch, pivot_hash
                );

                return Err(FilterError::UnknownBlock { hash: block_hash });
            }
        };

        Ok(Either::Right(self.filter_block_receipts(
            &filter,
            epoch,
            block_hash,
            receipts,
            block.transaction_hashes(/* space filter */ None),
        )))
    }

    fn filter_phantom_block<'a>(
        &self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64, pivot_hash: H256,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry> + 'a, FilterError> {
        // special case for genesis (for now, genesis has no logs)
        if epoch == 0 {
            return Ok(Either::Left(std::iter::empty()));
        }

        // check if epoch is still available
        let min = self.earliest_epoch_for_log_filter();

        if epoch < min {
            return Err(FilterError::EpochAlreadyPruned { epoch, min });
        }

        // filter block
        let epoch_bloom = match self.get_phantom_block_bloom_filter(
            EpochNumber::Number(epoch),
            pivot_hash,
        )? {
            Some(b) => b,
            None => {
                return Err(FilterError::BlockNotExecutedYet {
                    block_hash: pivot_hash,
                })
            }
        };

        if !bloom_possibilities
            .iter()
            .any(|bloom| epoch_bloom.contains_bloom(bloom))
        {
            return Ok(Either::Left(std::iter::empty()));
        }

        // construct phantom block
        let pb = match self.get_phantom_block_by_number(
            EpochNumber::Number(epoch),
            Some(pivot_hash),
            false, /* include_traces */
        )? {
            Some(b) => b,
            None => {
                return Err(FilterError::BlockNotExecutedYet {
                    block_hash: pivot_hash,
                })
            }
        };

        Ok(Either::Right(self.filter_block_receipts(
            &filter,
            epoch,
            pivot_hash,
            pb.receipts,
            pb.transactions.iter().map(|t| t.hash()).collect(),
        )))
    }

    fn filter_single_epoch<'a>(
        &'a self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // retrieve epoch hashes and pivot hash
        let mut epoch_hashes =
            self.inner.read_recursive().block_hashes_by_epoch(epoch)?;

        let pivot_hash = *epoch_hashes.last().expect("Epoch set not empty");

        // process hashes in reverse order
        epoch_hashes.reverse();

        if filter.space == Space::Ethereum {
            Ok(self
                .filter_phantom_block(
                    &filter,
                    &bloom_possibilities,
                    epoch,
                    pivot_hash,
                )?
                .collect())
        } else {
            epoch_hashes
                .into_iter()
                .map(move |block_hash| {
                    self.filter_block(
                        &filter,
                        &bloom_possibilities,
                        epoch,
                        pivot_hash,
                        block_hash,
                    )
                })
                // flatten results
                // Iterator<Result<Iterator<_>>> -> Iterator<Result<_>>
                .flat_map(|res| match res {
                    Ok(it) => Either::Left(it.map(Ok)),
                    Err(e) => Either::Right(std::iter::once(Err(e))),
                })
                .collect()
        }
    }

    fn filter_epoch_batch(
        &self, filter: &LogFilter, bloom_possibilities: &Vec<Bloom>,
        epochs: Vec<u64>, consistency_check_data: &mut Option<(u64, H256)>,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // lock so that we have a consistent view during this batch
        let inner = self.inner.read();

        // NOTE: as batches are processed atomically and only the
        // first batch (last few epochs) is likely to fluctuate, it is unlikely
        // that releasing the lock between batches would cause inconsistency:
        // we assume there are no pivot chain reorgs deeper than batch_size.
        // However, we still add a simple sanity check here:

        if let Some((epoch, pivot)) = *consistency_check_data {
            let new_pivot = inner.get_pivot_hash_from_epoch_number(epoch)?;

            if pivot != new_pivot {
                return Err(FilterError::PivotChainReorg {
                    epoch,
                    from: pivot,
                    to: new_pivot,
                });
            }
        }

        *consistency_check_data = Some((
            epochs[0],
            inner.get_pivot_hash_from_epoch_number(epochs[0])?,
        ));

        let epoch_batch_logs = epochs
            .into_par_iter() // process each epoch of this batch in parallel
            .map(|e| self.filter_single_epoch(filter, bloom_possibilities, e))
            .collect::<Result<Vec<Vec<LocalizedLogEntry>>, FilterError>>()?; // short-circuit on error

        Ok(epoch_batch_logs.into_iter().flatten().collect())
    }

    pub fn get_log_filter_epoch_range(
        &self, from_epoch: EpochNumber, to_epoch: EpochNumber,
        check_range: bool,
    ) -> Result<impl Iterator<Item = u64>, FilterError> {
        // lock so that we have a consistent view
        let _inner = self.inner.read_recursive();

        let from_epoch =
            self.get_height_from_epoch_number(from_epoch.clone())?;
        let to_epoch = self.get_height_from_epoch_number(to_epoch.clone())?;

        if from_epoch > to_epoch {
            return Err(FilterError::InvalidEpochNumber {
                from_epoch,
                to_epoch,
            });
        }

        if from_epoch < self.earliest_epoch_for_log_filter() {
            return Err(FilterError::EpochAlreadyPruned {
                epoch: from_epoch,
                min: self.earliest_epoch_for_log_filter(),
            });
        }

        if check_range {
            if let Some(max_gap) = self.config.get_logs_filter_max_epoch_range {
                // The range includes both ends.
                if to_epoch - from_epoch + 1 > max_gap {
                    return Err(FilterError::EpochNumberGapTooLarge {
                        from_epoch,
                        to_epoch,
                        max_gap,
                    });
                }
            }
        }

        return Ok((from_epoch..=to_epoch).rev());
    }

    pub fn get_trace_filter_epoch_range(
        &self, filter: &TraceFilter,
    ) -> Result<impl Iterator<Item = u64>, FilterError> {
        // lock so that we have a consistent view
        let _inner = self.inner.read_recursive();

        let from_epoch =
            self.get_height_from_epoch_number(filter.from_epoch.clone())?;
        let to_epoch =
            self.get_height_from_epoch_number(filter.to_epoch.clone())?;

        if from_epoch > to_epoch {
            return Err(FilterError::InvalidEpochNumber {
                from_epoch,
                to_epoch,
            });
        }

        if from_epoch < self.earliest_epoch_for_trace_filter() {
            return Err(FilterError::EpochAlreadyPruned {
                epoch: from_epoch,
                min: self.earliest_epoch_for_trace_filter(),
            });
        }
        Ok(from_epoch..=to_epoch)
    }

    fn filter_logs_by_epochs(
        &self, from_epoch: EpochNumber, to_epoch: EpochNumber,
        filter: &LogFilter, blocks_to_skip: HashSet<H256>, check_range: bool,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        let bloom_possibilities = filter.bloom_possibilities();

        // we store the last epoch processed and the corresponding pivot hash so
        // that we can check whether it changed between batches
        let mut consistency_check_data: Option<(u64, H256)> = None;

        let mut logs = self
            // iterate over epochs in reverse order
            .get_log_filter_epoch_range(from_epoch, to_epoch, check_range)?
            // we process epochs in each batch in parallel
            // but batches are processed one-by-one
            .chunks(self.config.get_logs_epoch_batch_size)
            .into_iter()
            .map(move |epochs| {
                self.filter_epoch_batch(
                    &filter,
                    &bloom_possibilities,
                    epochs.into_iter().collect(),
                    &mut consistency_check_data,
                )
            })
            // flatten results
            .flat_map(|res| match res {
                Ok(vec) => Either::Left(vec.into_iter().map(Ok)),
                Err(e) => Either::Right(std::iter::once(Err(e))),
            })
            // take as many as we need
            .skip_while(|res| match res {
                Ok(log) => blocks_to_skip.contains(&log.block_hash),
                Err(_) => false,
            })
            // Limit logs can return
            .take(
                self.config
                    .get_logs_filter_max_limit
                    .unwrap_or(::std::usize::MAX - 1)
                    + 1,
            )
            // short-circuit on error
            .collect::<Result<Vec<LocalizedLogEntry>, FilterError>>()?;

        logs.reverse();
        Ok(logs)
    }

       // collect epoch number, block index in epoch, block hash, pivot hash
       fn collect_block_info(
        &self, block_hash: H256,
    ) -> Result<(u64, usize, H256, H256), FilterError> {
        // special case for genesis
        if block_hash == self.data_man.true_genesis.hash() {
            return Ok((0, 0, block_hash, block_hash));
        }

        // check if block exists
        if self.data_man.block_header_by_hash(&block_hash).is_none() {
            bail!(FilterError::UnknownBlock { hash: block_hash });
        };

        // find pivot block
        let pivot_hash = match self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(&block_hash, false)
        {
            Some(r) => r.0,
            None => {
                match self.data_man.local_block_info_by_hash(&block_hash) {
                    // if local block info is not available, that means this
                    // block has never entered the consensus graph.
                    None => {
                        bail!(FilterError::BlockNotExecutedYet { block_hash })
                    }
                    // if the local block info is available, then it is very
                    // likely that we have already executed this block and the
                    // results are not available because they have been pruned.
                    // NOTE: it might be possible that the block has entered
                    // consensus graph but has not been executed yet, or that it
                    // was not executed because it was invalid. these cases seem
                    // rare enough to not require special handling here; we can
                    // add more fine-grained errors in the future if necessary.
                    Some(_) => {
                        bail!(FilterError::BlockAlreadyPruned { block_hash })
                    }
                }
            }
        };

        // find epoch number
        let epoch = match self.data_man.block_header_by_hash(&pivot_hash) {
            Some(h) => h.height(),
            None => {
                // internal error
                error!("Header of pivot block {:?} not found", pivot_hash);
                bail!(FilterError::UnknownBlock { hash: pivot_hash });
            }
        };

        let index_in_epoch = self
            .inner
            .read_recursive()
            .block_hashes_by_epoch(epoch)?
            .into_iter()
            .position(|h| h == block_hash)
            .expect("Block should exit in epoch set");

        Ok((epoch, index_in_epoch, block_hash, pivot_hash))
    }

    fn filter_logs_by_block_hashes(
        &self, block_hashes: Vec<H256>, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        let bloom_possibilities = filter.bloom_possibilities();

        // keep a consistent view during filtering
        let _inner = self.inner.read();

        // collect all block info in memory
        // note: we allow at most 128 block hashes so this should be fine
        let mut block_infos = block_hashes
            .into_par_iter()
            .map(|block_hash| self.collect_block_info(block_hash))
            .collect::<Result<Vec<_>, _>>()?;

        // lexicographic order will match execution order
        block_infos.sort();

        // process blocks in reverse
        block_infos.reverse();

        let mut logs = block_infos
            .into_iter()
            .map(|(epoch, _, block_hash, pivot_hash)| {
                self.filter_block(
                    &filter,
                    &bloom_possibilities,
                    epoch,
                    pivot_hash,
                    block_hash,
                )
            })
            // flatten results
            .flat_map(|res| match res {
                Ok(it) => Either::Left(it.into_iter().map(Ok)),
                Err(e) => Either::Right(std::iter::once(Err(e))),
            })
            // Limit logs can return
            .take(
                self.config
                    .get_logs_filter_max_limit
                    .unwrap_or(::std::usize::MAX - 1)
                    + 1,
            )
            // short-circuit on error
            .collect::<Result<Vec<_>, _>>()?;

        logs.reverse();
        Ok(logs)
    }

    fn filter_logs_by_block_numbers(
        &self, from_block: u64, to_block: u64, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // check range
        if from_block > to_block {
            return Err(FilterError::InvalidBlockNumber {
                from_block,
                to_block,
            });
        }

        if let Some(max_gap) =
            self.config.get_logs_filter_max_block_number_range
        {
            // The range includes both ends.
            if to_block - from_block + 1 > max_gap {
                return Err(FilterError::BlockNumberGapTooLarge {
                    from_block,
                    to_block,
                    max_gap,
                });
            }
        }

        // collect info from db
        let from_hash = match self
            .data_man
            .hash_by_block_number(from_block, true /* update_cache */)
        {
            Some(h) => h,
            None => bail!(FilterError::Custom(format!(
                "Unable to find block hash for from_block {:?}",
                from_block
            ))),
        };

        let to_hash = match self
            .data_man
            .hash_by_block_number(to_block, true /* update_cache */)
        {
            Some(h) => h,
            None => bail!(FilterError::Custom(format!(
                "Unable to find block hash for to_block {:?}",
                to_block
            ))),
        };

        let from_epoch = match self.get_block_epoch_number(&from_hash) {
            Some(e) => e,
            None => bail!(FilterError::Custom(format!(
                "Unable to find epoch number for block {:?}",
                from_hash
            ))),
        };

        let to_epoch = match self.get_block_epoch_number(&to_hash) {
            Some(e) => e,
            None => bail!(FilterError::Custom(format!(
                "Unable to find epoch number for block {:?}",
                to_hash
            ))),
        };

        let (from_epoch_hashes, to_epoch_hashes) = {
            let inner = self.inner.read();
            (
                inner.block_hashes_by_epoch(from_epoch)?,
                inner.block_hashes_by_epoch(to_epoch)?,
            )
        };

        // filter logs based on epochs
        // out-of-range blocks from the _end_ of the range
        // are handled by `filter_logs_by_epochs`
        let skip_from_end = to_epoch_hashes
            .into_iter()
            .skip_while(|h| *h != to_hash)
            .skip(1)
            .collect();

        let epoch_range_logs = self.filter_logs_by_epochs(
            EpochNumber::Number(from_epoch),
            EpochNumber::Number(to_epoch),
            &filter,
            skip_from_end,
            false, /* check_range */
        )?;

        // remove out-of-range blocks from the _start_ of the range
        let skip_from_start: HashSet<_> = from_epoch_hashes
            .into_iter()
            .take_while(|h| *h != from_hash)
            .collect();

        Ok(epoch_range_logs
            .into_iter()
            .skip_while(|log| skip_from_start.contains(&log.block_hash))
            .collect())
    }

    pub fn logs(
        &self, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        match &filter {
            // filter by epoch numbers
            LogFilter::EpochLogFilter {
                from_epoch,
                to_epoch,
                ..
            } => {
                // When query logs, if epoch number greater than
                // best_executed_state_epoch_number, use LatestState instead of
                // epoch number, in this case we can return logs from from_epoch
                // to LatestState
                let to_epoch = if let EpochNumber::Number(num) = to_epoch {
                    let epoch_number =
                        if *num > self.best_executed_state_epoch_number() {
                            EpochNumber::LatestState
                        } else {
                            to_epoch.clone()
                        };

                    epoch_number
                } else {
                    to_epoch.clone()
                };

                self.filter_logs_by_epochs(
                    from_epoch.clone(),
                    to_epoch,
                    &filter,
                    Default::default(),
                    !filter.trusted, /* check_range */
                )
            }

            // filter by block hashes
            LogFilter::BlockHashLogFilter { block_hashes, .. } => {
                self.filter_logs_by_block_hashes(block_hashes.clone(), filter)
            }

            // filter by block numbers
            LogFilter::BlockNumberLogFilter {
                from_block,
                to_block,
                ..
            } => self.filter_logs_by_block_numbers(
                from_block.clone(),
                to_block.clone(),
                filter,
            ),
        }
    }

    // TODO(lpl): Limit epoch range in filter.
    pub fn filter_traces(
        &self, mut filter: TraceFilter,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let traces = match filter.block_hashes.take() {
            None => self.filter_traces_by_epochs(&filter),
            Some(hashes) => self.filter_traces_by_block_hashes(&filter, hashes),
        }?;
        // Apply `filter.after` and `filter.count` after getting all trace
        // entries.
        Ok(traces
            .into_iter()
            .skip(filter.after.unwrap_or(0))
            .take(filter.count.unwrap_or(usize::max_value()))
            .collect())
    }
    
    pub fn collect_epoch_geth_trace(
        &self, epoch_num: u64, tx_hash: Option<H256>,
        opts: GethDebugTracingOptions,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        let epoch = EpochNumber::Number(epoch_num);
        self.validate_stated_epoch(&epoch)?;

        let epoch_block_hashes = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            v
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };

        let blocks = self
            .data_man
            .blocks_by_hash_list(
                &epoch_block_hashes,
                true, /* update_cache */
            )
            .expect("blocks exist");

        let pivot_block = blocks.last().expect("Not empty");
        let parent_pivot_block_hash = pivot_block.block_header.parent_hash();
        let parent_epoch_num = pivot_block.block_header.height() - 1;

        self.collect_blocks_geth_trace(
            *parent_pivot_block_hash,
            parent_epoch_num,
            &blocks,
            opts,
            tx_hash,
        )
    }

    pub fn collect_blocks_geth_trace(
        &self, epoch_id: H256, epoch_num: u64, blocks: &Vec<Arc<Block>>,
        opts: GethDebugTracingOptions, tx_hash: Option<H256>,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        self.executor.collect_blocks_geth_trace(
            epoch_id, epoch_num, blocks, opts, tx_hash,
        )
    }

    fn earliest_epoch_for_log_filter(&self) -> u64 {
        max(
            self.data_man.earliest_epoch_with_block_body(),
            self.data_man.earliest_epoch_with_execution_result(),
        )
    }

    fn filter_traces_by_epochs(
        &self, filter: &TraceFilter,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let epochs_and_pivot_hash = {
            let inner = self.inner.read();
            let mut epochs_and_pivot_hash = Vec::new();
            for epoch_number in self.get_trace_filter_epoch_range(filter)? {
                epochs_and_pivot_hash.push((
                    epoch_number,
                    inner.get_pivot_hash_from_epoch_number(epoch_number)?,
                ))
            }
            epochs_and_pivot_hash
        };

        let block_traces = epochs_and_pivot_hash
            .into_par_iter()
            .map(|(epoch_number, assumed_pivot)| {
                self.collect_traces_single_epoch(
                    filter,
                    epoch_number,
                    assumed_pivot,
                )
            })
            .collect::<Result<Vec<Vec<_>>, FilterError>>()?
            .into_iter()
            .flatten()
            .collect();

        self.filter_block_traces(filter, block_traces)
    }

    /// Return `Vec<(pivot_hash, block_hash, block_traces, block_txs)>`
    pub fn collect_traces_single_epoch(
        &self, filter: &TraceFilter, epoch_number: u64, assumed_pivot: H256,
    ) -> Result<
        Vec<(H256, H256, BlockExecTraces, Vec<Arc<SignedTransaction>>)>,
        FilterError,
    > {
        if filter.space == Space::Ethereum {
            let phantom_block = self
                .get_phantom_block_by_number(
                    EpochNumber::Number(epoch_number),
                    Some(assumed_pivot),
                    true, /* include_traces */
                )?
                .ok_or(FilterError::UnknownBlock {
                    hash: assumed_pivot,
                })?;

            return Ok(vec![(
                assumed_pivot,
                assumed_pivot,
                BlockExecTraces(phantom_block.traces),
                phantom_block.transactions,
            )]);
        }

        let block_hashes = self
            .inner
            .read_recursive()
            .block_hashes_by_epoch(epoch_number)?;
        if block_hashes.last().expect("epoch set not empty") != &assumed_pivot {
            bail!(FilterError::PivotChainReorg {
                epoch: epoch_number,
                from: assumed_pivot,
                to: *block_hashes.last().unwrap()
            })
        }
        let mut traces = Vec::new();
        for block_hash in block_hashes {
            let block = self
                .data_man
                .block_by_hash(&block_hash, false /* update_cache */)
                .ok_or(FilterError::BlockAlreadyPruned { block_hash })?;

            traces.push(
                self.data_man
                    .block_traces_by_hash_with_epoch(
                        &block_hash,
                        &assumed_pivot,
                        false,
                        true,
                    )
                    .map(|trace| {
                        (
                            assumed_pivot,
                            block_hash,
                            trace,
                            block.transactions.clone(),
                        )
                    })
                    .ok_or(FilterError::UnknownBlock { hash: block_hash })?,
            );
        }
        Ok(traces)
    }

    // TODO: We can apply some early return logic based on `filter.count`.
    fn filter_traces_by_block_hashes(
        &self, filter: &TraceFilter, block_hashes: Vec<H256>,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let block_traces = block_hashes
            .into_par_iter()
            .map(|h| {
                let block = self
                    .data_man
                    .block_by_hash(&h, false /* update_cache */)
                    .ok_or(FilterError::BlockAlreadyPruned { block_hash: h })?;

                self.data_man
                    .block_traces_by_hash(&h)
                    .map(|DataVersionTuple(pivot_hash, trace)| {
                        (pivot_hash, h, trace, block.transactions.clone())
                    })
                    .ok_or_else(|| FilterError::BlockNotExecutedYet {
                        block_hash: h,
                    })
            })
            .collect::<Result<Vec<_>, FilterError>>()?;
        self.filter_block_traces(filter, block_traces)
    }

    /// `block_traces` is a list of tuple `(pivot_hash, block_hash,
    /// block_trace)`.
    pub fn filter_block_traces(
        &self, filter: &TraceFilter,
        block_traces: Vec<(
            H256,
            H256,
            BlockExecTraces,
            Vec<Arc<SignedTransaction>>,
        )>,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let mut traces = Vec::new();
        for (pivot_hash, block_hash, block_trace, block_txs) in block_traces {
            if block_txs.len() != block_trace.0.len() {
                bail!(format!(
                    "tx list and trace length unmatch: block_hash={:?}",
                    block_hash
                ));
            }
            let epoch_number = self
                .data_man
                .block_height_by_hash(&pivot_hash)
                .ok_or_else(|| {
                    FilterError::Custom(
                        format!(
                            "pivot block header missing, hash={:?}",
                            pivot_hash
                        )
                        .into(),
                    )
                })?;
            let mut rpc_tx_index = 0;
            for (tx_pos, tx_trace) in block_trace.0.into_iter().enumerate() {
                if filter.space == Space::Native
                    && block_txs[tx_pos].space() == Space::Ethereum
                {
                    continue;
                }
                for trace in filter
                    .filter_traces(tx_trace)
                    .map_err(|e| FilterError::Custom(e))?
                {
                    if !filter
                        .action_types
                        .matches(&ActionType::from(&trace.action))
                    {
                        continue;
                    }
                    let trace = LocalizedTrace {
                        action: trace.action,
                        valid: trace.valid,
                        epoch_hash: pivot_hash,
                        epoch_number: epoch_number.into(),
                        block_hash,
                        transaction_position: rpc_tx_index.into(),
                        transaction_hash: block_txs[tx_pos].hash(),
                    };
                    traces.push(trace);
                }
                rpc_tx_index += 1;
            }
        }
        Ok(traces)
    }
}