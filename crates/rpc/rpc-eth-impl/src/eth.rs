use crate::helpers::{
    FeeHistoryCache, TxExecutor, MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
};
use alloy_primitives_wrapper::WAddress;
use alloy_rpc_types_eth::simulate::{
    SimBlock, SimCallResult, SimulateError, SimulatePayload, SimulatedBlock,
};
use async_trait::async_trait;
use cfx_executor::state::State;
use cfx_parameters::rpc::{GAS_PRICE_DEFAULT_VALUE, MAX_SIMULATE_BLOCKS};
use cfx_rpc_cfx_types::{
    traits::BlockProvider, PhantomBlock, RpcImplConfiguration,
};
use cfx_rpc_eth_api::EthApiServer;
use cfx_rpc_eth_types::{
    AccessListResult, AccountPendingTransactions, Block, BlockId,
    BlockOverrides, Bundle, EthCallResponse, EthRpcLogFilter,
    EthRpcLogFilter as Filter, EvmOverrides, FeeHistory, Header, Log, LogData,
    Receipt, RpcStateOverride, StateContext, StateOverride, SyncInfo,
    SyncStatus, Transaction, TransactionRequest,
};
use cfx_rpc_primitives::{Bytes, Index, U64 as HexU64};
use cfx_rpc_utils::{
    error::{
        errors::*, jsonrpc_error_helpers::*,
        jsonrpsee_error_helpers::internal_error as jsonrpsee_internal_error,
    },
    helpers::SpawnBlocking,
};
use cfx_statedb::StateDbExt;
use cfx_tasks::{TaskExecutor, TaskSpawner};
use cfx_types::{
    Address, AddressSpaceUtil, BigEndianHash, Bloom, Space, SpaceMap, H160,
    H256, H64, U256, U64,
};
use cfx_util_macros::bail;
use cfxcore::{
    errors::{Error as CoreError, Result as CoreResult},
    ConsensusGraph, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use cfxcore_errors::ProviderBlockError;
use jsonrpc_core::Error as RpcError;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use primitives::{
    filter::LogFilter,
    log_entry::LocalizedLogEntry,
    receipt::{BlockReturnDatas, EVM_SPACE_SUCCESS},
    Action, BlockHeaderBuilder, BlockReceipts, EpochNumber, StorageKey,
    StorageValue, TransactionStatus, TransactionWithSignature,
};
use std::{collections::HashMap, future::Future, sync::Arc};

type BlockNumber = BlockId;
type BlockNumberOrTag = BlockId;

type JsonStorageKey = U256;
type RpcBlock = Block;

#[derive(Clone)]
pub struct EthApi {
    config: RpcImplConfiguration,
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    fee_history_cache: FeeHistoryCache,
    tx_executor: TxExecutor,
    task_executor: TaskExecutor,
}

impl EthApi {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor,
    ) -> Self {
        let cloned_consensus = consensus.clone();
        let max_estimation_gas_limit = config.max_estimation_gas_limit;
        EthApi {
            config,
            consensus,
            sync,
            tx_pool,
            fee_history_cache: FeeHistoryCache::new(),
            tx_executor: TxExecutor::new(
                cloned_consensus,
                max_estimation_gas_limit,
            ),
            task_executor: executor,
        }
    }

    pub fn consensus_graph(&self) -> &ConsensusGraph { &self.consensus }

    pub fn tx_pool(&self) -> &SharedTransactionPool { &self.tx_pool }

    pub fn fetch_block_by_height(
        &self, height: u64,
    ) -> Result<PhantomBlock, ProviderBlockError> {
        self.consensus_graph()
            .get_phantom_block_by_number(
                EpochNumber::Number(height),
                None,
                false,
            )?
            .ok_or(
                format!("Specified block does not exist, height={}", height)
                    .into(),
            )
    }

    pub fn fetch_block_by_hash(
        &self, hash: &H256,
    ) -> Result<PhantomBlock, ProviderBlockError> {
        self.consensus_graph()
            .get_phantom_block_by_hash(hash, false)?
            .ok_or(
                format!("Specified block does not exist, hash={:?}", hash)
                    .into(),
            )
    }

    fn convert_block_number_to_epoch_number(
        &self, block_number: BlockNumber,
    ) -> Result<EpochNumber, String> {
        self.tx_executor
            .convert_block_number_to_epoch_number(block_number)
    }

    pub fn get_block_epoch_height(
        &self, block: BlockId,
    ) -> Result<u64, String> {
        let num = match block {
            BlockId::Num(block_number) => block_number,
            BlockId::Latest | BlockId::Safe | BlockId::Finalized => {
                let epoch_num = block.try_into().expect("should success");
                self.consensus_graph()
                    .get_height_from_epoch_number(epoch_num)?
            }
            BlockId::Hash {
                hash,
                require_canonical,
            } => self
                .consensus_graph()
                .get_block_epoch_number_with_pivot_check(
                    &hash,
                    require_canonical.unwrap_or_default(),
                )
                .map_err(|err| err.to_string())?,
            _ => return Err("not supported".to_string()),
        };
        Ok(num)
    }

    fn get_epoch_blocks(
        &self, epoch_num: EpochNumber,
    ) -> Result<Vec<Arc<primitives::Block>>, String> {
        let epoch_block_hashes = self
            .consensus_graph()
            .get_block_hashes_by_epoch(epoch_num)?;

        let epoch_blocks = self
            .consensus_graph()
            .data_man
            .blocks_by_hash_list(
                &epoch_block_hashes,
                true, /* update_cache */
            )
            .ok_or("blocks should exist".to_string())?;

        Ok(epoch_blocks)
    }

    pub fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> CoreResult<H256> {
        if self.sync.catch_up_mode() {
            bail!(request_rejected_in_catch_up_mode(None));
        }
        let (signed_trans, failed_trans) =
            self.tx_pool.insert_new_transactions(vec![tx]);
        if signed_trans.len() + failed_trans.len() > 1 {
            // This should never happen
            Ok(H256::zero().into())
        } else if signed_trans.len() + failed_trans.len() == 0 {
            // For tx in transactions_pubkey_cache, we simply ignore them
            bail!(RpcError::from(EthApiError::PoolError(
                RpcPoolError::AlreadyKnown
            )));
        } else if signed_trans.is_empty() {
            let tx_err = failed_trans.into_iter().next().expect("Not empty").1;
            bail!(RpcError::from(EthApiError::from(tx_err)))
        } else {
            let tx_hash = signed_trans[0].hash();
            self.sync.append_received_transactions(signed_trans);
            Ok(tx_hash.into())
        }
    }

    pub fn construct_rpc_receipt(
        &self, b: &PhantomBlock, idx: usize, prior_log_index: &mut usize,
    ) -> CoreResult<Receipt> {
        if b.transactions.len() != b.receipts.len() {
            return Err(internal_error(
                "Inconsistent state: transactions and receipts length mismatch",
            )
            .into());
        }

        if b.transactions.len() != b.errors.len() {
            return Err(internal_error(
                "Inconsistent state: transactions and errors length mismatch",
            )
            .into());
        }

        if idx >= b.transactions.len() {
            return Err(internal_error(
                "Inconsistent state: tx index out of bound",
            )
            .into());
        }

        let tx = &b.transactions[idx];
        let receipt = &b.receipts[idx];

        if receipt.logs.iter().any(|l| l.space != Space::Ethereum) {
            return Err(internal_error(
                "Inconsistent state: native tx in phantom block",
            )
            .into());
        }

        let contract_address = match receipt.outcome_status {
            TransactionStatus::Success => {
                Transaction::deployed_contract_address(tx)
            }
            _ => None,
        };

        let transaction_hash = tx.hash();
        let transaction_index: U256 = idx.into();
        let block_hash = b.pivot_header.hash();
        let block_height: U256 = b.pivot_header.height().into();

        let logs: Vec<_> = receipt
            .logs
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, log)| Log {
                inner: LogData {
                    address: log.address,
                    topics: log.topics,
                    data: log.data.into(),
                },
                block_hash,
                block_number: block_height,
                transaction_hash,
                transaction_index,
                block_timestamp: Some(b.pivot_header.timestamp().into()),
                log_index: Some((*prior_log_index + idx).into()),
                transaction_log_index: Some(idx.into()),
                removed: false,
            })
            .collect();

        *prior_log_index += logs.len();

        let gas_used = match idx {
            0 => receipt.accumulated_gas_used,
            idx => {
                receipt.accumulated_gas_used
                    - b.receipts[idx - 1].accumulated_gas_used
            }
        };

        let tx_exec_error_msg = if b.errors[idx].is_empty() {
            None
        } else {
            Some(b.errors[idx].clone())
        };

        let effective_gas_price =
            if let Some(base_price) = b.pivot_header.base_price() {
                let base_price = base_price[tx.space()];
                if *tx.gas_price() < base_price {
                    *tx.gas_price()
                } else {
                    tx.effective_gas_price(&base_price)
                }
            } else {
                *tx.gas_price()
            };

        Ok(Receipt {
            transaction_hash,
            transaction_index,
            block_hash,
            from: tx.sender().address,
            to: match tx.action() {
                Action::Create => None,
                Action::Call(addr) => Some(addr),
            },
            block_number: block_height,
            cumulative_gas_used: receipt.accumulated_gas_used,
            gas_used,
            gas_fee: receipt.gas_fee,
            contract_address,
            logs,
            logs_bloom: receipt.log_bloom,
            status_code: receipt
                .outcome_status
                .in_space(Space::Ethereum)
                .into(),
            effective_gas_price,
            tx_exec_error_msg,
            transaction_type: receipt
                .burnt_gas_fee
                .is_some()
                .then_some(U64::from(tx.type_id())),
            burnt_gas_fee: receipt.burnt_gas_fee,
        })
    }

    pub fn get_tx_from_txpool(&self, hash: H256) -> Option<Transaction> {
        let tx = self.tx_pool.get_transaction(&hash)?;

        if tx.space() == Space::Ethereum {
            Some(Transaction::from_signed(
                &tx,
                (None, None, None),
                (None, None),
            ))
        } else {
            None
        }
    }

    pub fn get_block_receipts(
        &self, block_num: BlockNumber,
    ) -> CoreResult<Vec<Receipt>> {
        let b = {
            let phantom_block = self.phantom_block_by_number(block_num)?;

            match phantom_block {
                None => return Err(unknown_block().into()),
                Some(b) => b,
            }
        };

        let mut block_receipts = vec![];
        let mut prior_log_index = 0;

        for idx in 0..b.receipts.len() {
            block_receipts.push(self.construct_rpc_receipt(
                &b,
                idx,
                &mut prior_log_index,
            )?);
        }

        return Ok(block_receipts);
    }

    pub fn block_tx_by_index(
        phantom_block: Option<PhantomBlock>, idx: usize,
    ) -> Option<Transaction> {
        match phantom_block {
            None => None,
            Some(pb) => match pb.transactions.get(idx) {
                None => None,
                Some(tx) => {
                    let block_number = Some(pb.pivot_header.height().into());
                    let receipt = pb.receipts.get(idx).unwrap();
                    let status =
                        receipt.outcome_status.in_space(Space::Ethereum);
                    let contract_address = match status == EVM_SPACE_SUCCESS {
                        true => Transaction::deployed_contract_address(&tx),
                        false => None,
                    };
                    Some(Transaction::from_signed(
                        &tx,
                        (
                            Some(pb.pivot_header.hash()),
                            block_number,
                            Some(idx.into()),
                        ),
                        (Some(status.into()), contract_address),
                    ))
                }
            },
        }
    }

    pub fn sync_status(&self) -> SyncStatus {
        if self.sync.catch_up_mode() {
            SyncStatus::Info(SyncInfo {
                starting_block: U256::from(self.consensus.block_count()),
                current_block: U256::from(self.consensus.block_count()),
                highest_block: U256::from(
                    self.sync.get_synchronization_graph().block_count(),
                ),
                warp_chunks_amount: None,
                warp_chunks_processed: None,
            })
        } else {
            SyncStatus::None
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.consensus.best_chain_id().in_evm_space()
    }

    pub fn gas_price(&self) -> U256 {
        let (_, maybe_base_price) =
            self.tx_pool.get_best_info_with_parent_base_price();
        if let Some(base_price) = maybe_base_price {
            return base_price[Space::Ethereum];
        }

        let consensus_gas_price = self
            .consensus_graph()
            .gas_price(Space::Ethereum)
            .unwrap_or(GAS_PRICE_DEFAULT_VALUE.into());
        std::cmp::max(
            consensus_gas_price,
            self.tx_pool.config.min_eth_tx_price.into(),
        )
    }

    pub fn latest_block_number(&self) -> CoreResult<U256> {
        let consensus_graph = self.consensus_graph();
        let epoch_num = EpochNumber::LatestState;
        match consensus_graph.get_height_from_epoch_number(epoch_num.into()) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e).into()),
        }
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.consensus.best_epoch_number()
    }

    pub fn user_balance(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> CoreResult<U256> {
        let epoch_num =
            self.convert_block_number_to_epoch_number(num.unwrap_or_default())?;
        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&address.with_evm_space())
            .map_err(|err| CoreError::from(err))?;

        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    pub fn storage_at(
        &self, address: H160, position: U256, block_num: Option<BlockNumber>,
    ) -> CoreResult<H256> {
        let epoch_num = self.convert_block_number_to_epoch_number(
            block_num.unwrap_or_default(),
        )?;

        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "epoch_number")?;

        let position: H256 = H256::from_uint(&position);

        let key = StorageKey::new_storage_key(&address, position.as_ref())
            .with_evm_space();

        Ok(
            match state_db
                .get::<StorageValue>(key)
                .map_err(|err| CoreError::from(err))?
            {
                Some(entry) => H256::from_uint(&entry.value).into(),
                None => H256::zero(),
            },
        )
    }

    pub fn phantom_block_by_hash(
        &self, hash: H256,
    ) -> CoreResult<Option<PhantomBlock>> {
        self.phantom_block_by_number(BlockNumber::Hash {
            hash,
            require_canonical: None,
        })
    }

    pub fn phantom_block_by_number(
        &self, block_num: BlockNumber,
    ) -> CoreResult<Option<PhantomBlock>> {
        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            match block_num {
                BlockNumber::Hash { hash, .. } => {
                    self.consensus_graph()
                        .get_phantom_block_by_hash(
                            &hash, false, /* include_traces */
                        )
                        .map_err(RpcError::invalid_params)?
                }
                _ => {
                    match self.consensus_graph().get_phantom_block_by_number(
                        block_num.try_into()?,
                        None,
                        false, /* include_traces */
                    ) {
                        Ok(pb) => pb,
                        Err(e) => match e {
                            ProviderBlockError::Common(e) => {
                                return Err(RpcError::invalid_params(e).into());
                            }
                            ProviderBlockError::EpochNumberTooLarge => None,
                        },
                    }
                }
            }
        };

        Ok(phantom_block)
    }

    pub fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> CoreResult<Option<RpcBlock>> {
        let phantom_block = self.phantom_block_by_hash(hash)?;

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(RpcBlock::from_phantom(&pb, include_txs))),
        }
    }

    pub fn block_by_number(
        &self, block_num: BlockNumber, include_txs: bool,
    ) -> CoreResult<Option<RpcBlock>> {
        let phantom_block = self.phantom_block_by_number(block_num)?;

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(RpcBlock::from_phantom(&pb, include_txs))),
        }
    }

    pub fn next_nonce(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> CoreResult<U256> {
        let nonce = match num {
            Some(BlockNumber::Pending) => {
                self.tx_pool.get_next_nonce(&address.with_evm_space())
            }
            _ => self.consensus_graph().next_nonce(
                address.with_evm_space(),
                num.unwrap_or_default().into(),
                "num",
            )?,
        };

        Ok(nonce)
    }

    pub fn block_transaction_count_by_hash(
        &self, hash: H256,
    ) -> CoreResult<Option<U256>> {
        let phantom_block = self.phantom_block_by_hash(hash)?;

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(pb.transactions.len().into())),
        }
    }

    pub fn block_transaction_count_by_number(
        &self, block_num: BlockNumber,
    ) -> CoreResult<Option<U256>> {
        let phantom_block = self.phantom_block_by_number(block_num)?;

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(pb.transactions.len().into())),
        }
    }

    pub fn block_uncles_count_by_hash(
        &self, hash: H256,
    ) -> CoreResult<Option<U256>> {
        let epoch_num = match self.consensus.get_block_epoch_number(&hash) {
            None => return Ok(None),
            Some(n) => n,
        };

        let maybe_pivot_hash = self
            .consensus
            .get_block_hashes_by_epoch(epoch_num.into())
            .ok()
            .and_then(|hs| hs.last().cloned());

        match maybe_pivot_hash {
            Some(h) if h == hash => Ok(Some(0.into())),
            _ => Ok(None),
        }
    }

    pub fn block_uncles_count_by_number(
        &self, block_num: BlockNumber,
    ) -> CoreResult<Option<U256>> {
        let epoch_num = self.convert_block_number_to_epoch_number(block_num)?;
        let maybe_epoch =
            self.consensus.get_block_hashes_by_epoch(epoch_num).ok();

        Ok(maybe_epoch.map(|_| 0.into()))
    }

    pub fn code_at(
        &self, address: H160, block_num: Option<BlockNumber>,
    ) -> CoreResult<Bytes> {
        let epoch_num = self.convert_block_number_to_epoch_number(
            block_num.unwrap_or_default(),
        )?;

        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "num")?;

        let address = address.with_evm_space();

        let code = match state_db
            .get_account(&address)
            .map_err(|err| CoreError::from(err))?
        {
            Some(acc) => match state_db
                .get_code(&address, &acc.code_hash)
                .map_err(|err| CoreError::from(err))?
            {
                Some(code) => (*code.code).clone(),
                _ => vec![],
            },
            None => vec![],
        };

        Ok(Bytes::new(code))
    }

    pub fn fee_history(
        &self, mut block_count: HexU64, newest_block: BlockNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> CoreResult<FeeHistory> {
        if block_count.as_u64() == 0 || newest_block == BlockNumber::Pending {
            return Ok(FeeHistory::new());
        }

        if block_count.as_u64() > MAX_FEE_HISTORY_CACHE_BLOCK_COUNT {
            block_count = HexU64::from(MAX_FEE_HISTORY_CACHE_BLOCK_COUNT);
        }

        if let Some(percentiles) = &reward_percentiles {
            if percentiles.windows(2).any(|w| w[0] > w[1] || w[0] > 100.) {
                return Err(RpcError::from(
                    EthApiError::InvalidRewardPercentiles,
                )
                .into());
            }
        }
        let reward_percentiles = reward_percentiles.unwrap_or_default();

        // keep read lock to ensure consistent view
        let _consensus = self.consensus_graph().inner.read();

        let epoch_num =
            self.convert_block_number_to_epoch_number(newest_block)?;
        let newest_height: u64 = self
            .consensus_graph()
            .get_height_from_epoch_number(epoch_num)
            .map_err(RpcError::invalid_params)?;

        if newest_block == BlockNumber::Latest {
            let fetch_block_by_hash = |height| {
                self.fetch_block_by_hash(&height).map_err(|e| e.to_string())
            };

            let latest_block = self
                .fetch_block_by_height(newest_height)
                .map_err(|e| internal_rpc_err(e.to_string()))?;

            self.fee_history_cache
                .update_to_latest_block(
                    newest_height,
                    latest_block.pivot_header.hash(),
                    block_count.as_u64(),
                    fetch_block_by_hash,
                )
                .map_err(|e| internal_rpc_err(e.to_string()))?;
        }

        let mut fee_history = FeeHistory::new();

        let end_block = newest_height;
        let start_block = if end_block >= block_count.as_u64() {
            end_block - block_count.as_u64() + 1
        } else {
            0
        };

        let mut cached_fee_history_entries = self
            .fee_history_cache
            .get_history_with_missing_info(start_block, end_block);

        cached_fee_history_entries.reverse();
        for (i, entry) in cached_fee_history_entries.into_iter().enumerate() {
            if entry.is_none() {
                let height = end_block - i as u64;
                let block = self
                    .fetch_block_by_height(height)
                    .map_err(RpcError::invalid_params)?;

                // Internal error happens only if the fetch header has
                // inconsistent block height
                fee_history
                    .push_front_block(
                        Space::Ethereum,
                        &reward_percentiles,
                        &block.pivot_header,
                        block.transactions.iter().map(|x| &**x),
                    )
                    .map_err(|_| RpcError::internal_error())?;
            } else {
                fee_history
                    .push_front_entry(&entry.unwrap(), &reward_percentiles)
                    .expect("always success");
            }
        }

        let last_hash = self
            .consensus_graph()
            .get_hash_from_epoch_number((end_block + 1).into())?;
        let last_header = self
            .consensus_graph()
            .data_manager()
            .block_header_by_hash(&last_hash)
            .ok_or_else(|| {
                format!("last block missing, height={}", end_block + 1)
            })?;

        fee_history.finish(
            start_block,
            last_header.base_price().as_ref(),
            Space::Ethereum,
        );

        Ok(fee_history)
    }

    pub fn transaction_by_hash(
        &self, hash: H256,
    ) -> CoreResult<Option<Transaction>> {
        let tx_index = match self
            .consensus
            .data_manager()
            .transaction_index_by_hash(&hash, false /* update_cache */)
        {
            None => return Ok(self.get_tx_from_txpool(hash)),
            Some(tx_index) => tx_index,
        };

        let epoch_num =
            match self.consensus.get_block_epoch_number(&tx_index.block_hash) {
                None => return Ok(self.get_tx_from_txpool(hash)),
                Some(n) => n,
            };

        let maybe_block = self
            .consensus_graph()
            .get_phantom_block_by_number(
                EpochNumber::Number(epoch_num),
                None,
                false, /* include_traces */
            )
            .map_err(RpcError::invalid_params)?;

        let phantom_block = match maybe_block {
            None => return Ok(self.get_tx_from_txpool(hash)),
            Some(b) => b,
        };

        for (idx, tx) in phantom_block.transactions.iter().enumerate() {
            if tx.hash() == hash {
                let tx = Self::block_tx_by_index(Some(phantom_block), idx);
                if let Some(tx_ref) = &tx {
                    if tx_ref.status
                        == Some(
                            TransactionStatus::Skipped
                                .in_space(Space::Ethereum)
                                .into(),
                        )
                    {
                        // A skipped transaction is not available to clients if
                        // accessed by its hash.
                        return Ok(None);
                    }
                }
                return Ok(tx);
            }
        }

        Ok(self.get_tx_from_txpool(hash))
    }

    pub fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> CoreResult<Option<Receipt>> {
        let tx_index =
            match self.consensus.data_manager().transaction_index_by_hash(
                &tx_hash, false, /* update_cache */
            ) {
                None => return Ok(None),
                Some(tx_index) => tx_index,
            };

        let epoch_num =
            match self.consensus.get_block_epoch_number(&tx_index.block_hash) {
                None => return Ok(None),
                Some(n) => n,
            };

        if epoch_num > self.consensus_graph().best_executed_state_epoch_number()
        {
            // The receipt is only visible to optimistic execution.
            return Ok(None);
        }

        let maybe_block = self
            .consensus_graph()
            .get_phantom_block_by_number(
                EpochNumber::Number(epoch_num),
                None,
                false, /* include_traces */
            )
            .map_err(RpcError::invalid_params)?;

        let phantom_block = match maybe_block {
            None => return Ok(None),
            Some(b) => b,
        };

        let mut prior_log_index = 0;

        for (idx, tx) in phantom_block.transactions.iter().enumerate() {
            if tx.hash() == tx_hash {
                let receipt = self.construct_rpc_receipt(
                    &phantom_block,
                    idx,
                    &mut prior_log_index,
                )?;
                // A skipped transaction is not available to clients if accessed
                // by its hash.
                if receipt.status_code
                    == TransactionStatus::Skipped
                        .in_space(Space::Ethereum)
                        .into()
                {
                    return Ok(None);
                }

                return Ok(Some(receipt));
            }

            // if the if-branch was not entered, we do the bookkeeping here
            prior_log_index += phantom_block.receipts[idx].logs.len();
        }

        Ok(None)
    }

    pub fn logs(&self, filter: EthRpcLogFilter) -> CoreResult<Vec<Log>> {
        let filter: LogFilter = filter.into_primitive(self)?;

        let logs = self
            .consensus_graph()
            .logs(filter)
            .map_err(|err| CoreError::from(err))?;

        // If the results does not fit into `max_limit`, report an error
        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if logs.len() > max_limit {
                bail!(invalid_params("filter", format!("This query results in too many logs, max limitation is {}, please use a smaller block range", max_limit)));
            }
        }

        Ok(logs
            .iter()
            .cloned()
            .map(|l| Log::try_from_localized(l, self, false))
            .collect::<Result<_, _>>()?)
    }

    pub fn max_priority_fee_per_gas(&self) -> CoreResult<U256> {
        let evm_ratio =
            self.tx_pool.machine().params().evm_transaction_block_ratio
                as usize;

        let fee_history = self.fee_history(
            HexU64::from(300),
            BlockNumber::Latest,
            Some(vec![50f64]),
        )?;

        let total_reward: U256 = fee_history
            .reward()
            .iter()
            .map(|x| x.first().unwrap())
            .fold(U256::zero(), |x, y| x + *y);

        Ok(total_reward * evm_ratio / 300)
    }

    pub fn account_pending_transactions(
        &self, address: Address, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> CoreResult<AccountPendingTransactions> {
        let (pending_txs, tx_status, pending_count) = self
            .tx_pool()
            .get_account_pending_transactions(
                &Address::from(address).with_evm_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.best_epoch_number(),
            )
            .map_err(|e| CoreError::from(e))?;
        Ok(AccountPendingTransactions {
            pending_transactions: pending_txs
                .into_iter()
                .map(|tx| {
                    Transaction::from_signed(
                        &tx,
                        (None, None, None),
                        (None, None),
                    )
                })
                .collect(),
            first_tx_status: tx_status,
            pending_count: pending_count.into(),
        })
    }

    pub fn simulate_v1(
        &self, payload: SimulatePayload, block_id: Option<BlockId>,
    ) -> CoreResult<Vec<SimulatedBlock<Block>>> {
        let SimulatePayload {
            block_state_calls,
            trace_transfers, // not implemented for v1
            validation: _,   // ignored for v1
            return_full_transactions,
        } = payload;

        if block_state_calls.is_empty() {
            return Err(RpcError::invalid_params(String::from(
                "calls are empty.",
            ))
            .into());
        }

        if block_state_calls.len() > MAX_SIMULATE_BLOCKS as usize {
            return Err(RpcError::invalid_params(
                "too many blocks.".to_string(),
            )
            .into());
        }

        let chain_id = self.consensus.best_chain_id();

        let block_number = block_id.unwrap_or_default();

        let epoch_blocks = self.get_epoch_blocks(
            self.convert_block_number_to_epoch_number(block_number)?,
        )?;
        let epoch_block = epoch_blocks.last().expect("exist");

        let epoch_hash = epoch_block.hash();
        let epoch_height = epoch_block.block_header.height();

        let mut start_block_number = self
            .consensus_graph()
            .data_man
            .get_epoch_execution_context(&epoch_hash)
            .map(|v| v.start_block_number)
            .expect("should exist");

        let state_db = self.consensus_graph().get_state_db_by_epoch_number(
            EpochNumber::Number(epoch_height),
            "num",
        )?;
        let mut state = State::new(state_db)?;

        let mut prev_block = epoch_block.clone();

        let mut res = vec![];

        let mut next_nonces: HashMap<Address, U256> = HashMap::new();

        for block_call in block_state_calls {
            let SimBlock {
                block_overrides,
                state_overrides,
                calls,
            } = block_call;

            // check state_overrides validity
            if let Some(state_overrides_ref) = &state_overrides {
                let both_state_present =
                    state_overrides_ref.iter().any(|(_a, account_override)| {
                        account_override.state.is_some()
                            && account_override.state_diff.is_some()
                    });
                if both_state_present {
                    return Err(RpcError::invalid_params(String::from(
                        "Both 'state' and 'stateDiff' are present in account override",
                    ))
                    .into());
                }
            }

            // apply block overrides
            let evm_overrides = EvmOverrides::new(
                state_overrides.map(|v| {
                    v.into_iter()
                        .map(|(k, v)| {
                            (
                                WAddress::from(k).into(),
                                v.try_into().expect("success"),
                            )
                        })
                        .collect::<StateOverride>()
                }),
                block_overrides.map(|v| Box::new(v.into())),
            );

            if let Some(state_overrides_ref) = &evm_overrides.state {
                state.apply_override(state_overrides_ref, Space::Ethereum)?;
            }

            let mut header_builder = BlockHeaderBuilder::new();
            header_builder
                .with_parent_hash(prev_block.hash())
                .with_height(prev_block.block_header.height() + 1)
                .with_timestamp(prev_block.block_header.timestamp() + 1) // one block one second
                .with_gas_limit(*prev_block.block_header.gas_limit())
                .with_base_price(prev_block.block_header.base_price());

            // apply block overrides
            if let Some(block_overrides_ref) = &evm_overrides.block {
                if let Some(_number) = block_overrides_ref.number {
                    // need override the start_block_number
                }

                if let Some(difficulty) = block_overrides_ref.difficulty {
                    header_builder.with_difficulty(difficulty);
                }

                if let Some(time) = block_overrides_ref.time {
                    header_builder.with_timestamp(time);
                }

                if let Some(gas_limit) = block_overrides_ref.gas_limit {
                    header_builder.with_gas_limit(gas_limit.into());
                }

                if let Some(coinbase) = block_overrides_ref.coinbase {
                    header_builder.with_author(coinbase);
                }

                if let Some(_random) = block_overrides_ref.random {
                    // conflux does not support random(prevRandao)
                }

                if let Some(base_fee) = block_overrides_ref.base_fee {
                    let space_base_fee = SpaceMap::new(base_fee, base_fee);
                    header_builder.with_base_price(Some(space_base_fee));
                }

                if let Some(_block_hash) = &block_overrides_ref.block_hash {
                    // not supported
                }
            }

            let mut local_calls: Vec<TransactionRequest> = calls
                .into_iter()
                .map(|c| TransactionRequest::from(c))
                .collect();

            // normalize transactions: check & auto fill nonce
            for tx in &mut local_calls {
                let sender = tx.from.unwrap_or_default();
                if !next_nonces.contains_key(&sender) {
                    let nonce = state.nonce(&sender.with_evm_space())?;
                    next_nonces.insert(sender, nonce);
                }
                let expected_nonce =
                    next_nonces.get_mut(&sender).expect("should exist");
                if let Some(nonce) = tx.nonce {
                    if nonce != *expected_nonce {
                        return Err(RpcError::invalid_params(format!(
                            "Invalid nonce for address {:?}: expected {}, got {}",
                            sender, expected_nonce, nonce
                        ))
                        .into());
                    }
                } else {
                    tx.nonce = Some(*expected_nonce);
                }
                *expected_nonce += U256::one();
            }

            let signed_txs = local_calls
                .into_iter()
                .map(|tx| {
                    Arc::new(
                        tx.sign_call(
                            chain_id.in_evm_space(),
                            self.config.max_estimation_gas_limit,
                        )
                        .expect("should success"),
                    )
                })
                .collect();

            let block = Arc::new(primitives::Block::new(
                header_builder.build(),
                signed_txs,
            ));
            let epoch_blocks: Vec<Arc<primitives::Block>> = vec![block.clone()];

            let (block_receipts, block_return_datas) =
                self.consensus_graph().collect_blocks_exec_result(
                    &mut state,
                    &epoch_blocks,
                    trace_transfers,
                    start_block_number,
                )?;

            if block_receipts.len() != 1 {
                return Err(internal_error(
                    "Inconsistent state: block_receipts and blocks length mismatch",
                )
                .into());
            }
            if block_receipts.len() != block_return_datas.len() {
                return Err(internal_error(
                    "Inconsistent state: block_receipts and return_datas length mismatch",
                )
                .into());
            }

            let simulated_block = Self::construct_simulated_block(
                &block,
                &block_receipts,
                &block_return_datas,
                return_full_transactions,
            );
            res.push(simulated_block);

            start_block_number += 1;
            prev_block = block;
        }

        Ok(res)
    }

    fn construct_simulated_block(
        block: &primitives::Block, block_receipts: &Vec<Arc<BlockReceipts>>,
        block_return_datas: &Vec<BlockReturnDatas>, full_transactions: bool,
    ) -> SimulatedBlock<Block> {
        let mut calls: Vec<SimCallResult> = vec![];
        let mut prev_gas_used: u64 = 0;
        let mut log_index: usize = 0;
        let mut bloom: Bloom = Default::default();
        for (idx, receipt) in block_receipts[0].receipts.iter().enumerate() {
            let return_data = block_return_datas[0].return_datas[idx].clone();
            let err_msg =
                block_receipts[0].tx_execution_error_messages[idx].clone();
            let error = if err_msg.is_empty() {
                None
            } else {
                Some(SimulateError {
                    code: -3200, /* -3200: Execution reverted  -32015: VM
                                  * execution error */
                    message: err_msg,
                })
            };

            let status = match receipt.outcome_status {
                TransactionStatus::Success => true,
                _ => false,
            };
            let gas_used =
                receipt.accumulated_gas_used.as_u64() - prev_gas_used;
            prev_gas_used = receipt.accumulated_gas_used.as_u64();

            bloom.accrue_bloom(&receipt.log_bloom);

            let mut logs = vec![];

            for (index, log) in receipt.logs.iter().enumerate() {
                if log.space == Space::Ethereum {
                    log_index += 1;
                    logs.push(
                        Log::from_localized(
                            LocalizedLogEntry {
                                entry: log.clone(),
                                block_hash: block.hash(),
                                epoch_number: block.block_header.height(),
                                block_timestamp: Some(
                                    block.block_header.timestamp(),
                                ),
                                transaction_hash: block.transactions[idx]
                                    .hash(),
                                transaction_index: idx,
                                log_index,
                                transaction_log_index: index,
                            },
                            block.hash(),
                            false,
                        )
                        .into(),
                    );
                }
            }
            calls.push(SimCallResult {
                return_data: return_data.into(),
                logs,
                gas_used,
                status,
                error,
            });
        }

        let phantom_block = PhantomBlock {
            pivot_header: block.block_header.clone(),
            transactions: block.transactions.clone(),
            receipts: block_receipts[0].receipts.clone(),
            errors: block_receipts[0].tx_execution_error_messages.clone(),
            bloom,
            traces: Default::default(),
            total_gas_limit: block.block_header.gas_limit().clone(),
        };
        SimulatedBlock {
            inner: Block::from_phantom(&phantom_block, full_transactions),
            calls,
        }
    }
}

impl SpawnBlocking for EthApi {
    fn io_task_spawner(&self) -> impl TaskSpawner { self.task_executor.clone() }
}

impl EthApi {
    pub fn async_transaction_by_hash(
        &self, hash: H256,
    ) -> impl Future<Output = Result<Option<Transaction>, ErrorObjectOwned>> + Send
    {
        let self_clone = self.clone();
        async move {
            let resp = self_clone
                .spawn_blocking_io(move |this| {
                    this.transaction_by_hash(hash).map_err(|err| err.into())
                })
                .await;
            resp
        }
    }
}

impl BlockProvider for &EthApi {
    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.consensus_graph().get_block_epoch_number(hash)
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.consensus_graph()
            .get_block_hashes_by_epoch(epoch_number)
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    /// Returns the protocol version encoded as a string.
    async fn protocol_version(&self) -> RpcResult<U64> { Ok(U64::from(65)) }

    /// Returns an object with data about the sync status or false.
    fn syncing(&self) -> RpcResult<SyncStatus> { Ok(self.sync_status()) }

    /// Returns the client coinbase address.
    async fn author(&self) -> RpcResult<Address> { Ok(H160::zero()) }

    /// Returns a list of addresses owned by client.
    fn accounts(&self) -> RpcResult<Vec<Address>> { Ok(vec![]) }

    /// Returns the number of most recent block.
    fn block_number(&self) -> RpcResult<U256> {
        self.latest_block_number().map_err(Into::into)
    }

    /// Returns the chain ID of the current network.
    async fn chain_id(&self) -> RpcResult<Option<U64>> {
        Ok(Some(self.chain_id().into()))
    }

    /// Returns information about a block by hash.
    async fn block_by_hash(
        &self, hash: H256, full: bool,
    ) -> RpcResult<Option<Block>> {
        self.block_by_hash(hash, full).map_err(Into::into)
    }

    /// Returns information about a block by number.
    async fn block_by_number(
        &self, number: BlockNumberOrTag, full: bool,
    ) -> RpcResult<Option<Block>> {
        self.block_by_number(number, full).map_err(Into::into)
    }

    /// Returns the number of transactions in a block from a block matching the
    /// given block hash.
    async fn block_transaction_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        self.block_transaction_count_by_hash(hash)
            .map_err(Into::into)
    }

    /// Returns the number of transactions in a block matching the given block
    /// number.
    async fn block_transaction_count_by_number(
        &self, number: BlockNumberOrTag,
    ) -> RpcResult<Option<U256>> {
        self.block_transaction_count_by_number(number)
            .map_err(Into::into)
    }

    /// Returns the number of uncles in a block from a block matching the given
    /// block hash.
    async fn block_uncles_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        self.block_uncles_count_by_hash(hash).map_err(Into::into)
    }

    /// Returns the number of uncles in a block with given block number.
    async fn block_uncles_count_by_number(
        &self, number: BlockNumberOrTag,
    ) -> RpcResult<Option<U256>> {
        self.block_uncles_count_by_number(number)
            .map_err(Into::into)
    }

    /// Returns all transaction receipts for a given block.
    async fn block_receipts(
        &self, block_id: BlockId,
    ) -> RpcResult<Option<Vec<Receipt>>> {
        self.get_block_receipts(block_id)
            .map(|val| Some(val))
            .map_err(Into::into)
    }

    /// Returns an uncle block of the given block and index.
    async fn uncle_by_block_hash_and_index(
        &self, hash: H256, index: Index,
    ) -> RpcResult<Option<Block>> {
        let _ = (hash, index);
        Ok(None)
    }

    /// Returns an uncle block of the given block and index.
    async fn uncle_by_block_number_and_index(
        &self, number: BlockNumberOrTag, index: Index,
    ) -> RpcResult<Option<Block>> {
        let _ = (number, index);
        Ok(None)
    }

    /// Returns the EIP-2718 encoded transaction if it exists.
    ///
    /// If this is a EIP-4844 transaction that is in the pool it will include
    /// the sidecar.
    async fn raw_transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<Bytes>> {
        let _ = hash;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Returns the information about a transaction requested by transaction
    /// hash.
    async fn transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<Transaction>> {
        self.async_transaction_by_hash(hash).await
    }

    /// Returns information about a raw transaction by block hash and
    /// transaction index position.
    async fn raw_transaction_by_block_hash_and_index(
        &self, hash: H256, index: Index,
    ) -> RpcResult<Option<Bytes>> {
        let _ = (hash, index);
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Returns information about a transaction by block hash and transaction
    /// index position.
    async fn transaction_by_block_hash_and_index(
        &self, hash: H256, index: Index,
    ) -> RpcResult<Option<Transaction>> {
        let phantom_block = self.phantom_block_by_hash(hash)?;

        Ok(EthApi::block_tx_by_index(phantom_block, index.value()))
    }

    /// Returns information about a raw transaction by block number and
    /// transaction index position.
    async fn raw_transaction_by_block_number_and_index(
        &self, number: BlockNumberOrTag, index: Index,
    ) -> RpcResult<Option<Bytes>> {
        let _ = (number, index);
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Returns information about a transaction by block number and transaction
    /// index position.
    async fn transaction_by_block_number_and_index(
        &self, number: BlockNumberOrTag, index: Index,
    ) -> RpcResult<Option<Transaction>> {
        let phantom_block = self.phantom_block_by_number(number)?;

        Ok(EthApi::block_tx_by_index(phantom_block, index.value()))
    }

    /// Returns information about a transaction by sender and nonce.
    async fn transaction_by_sender_and_nonce(
        &self, address: Address, nonce: U64,
    ) -> RpcResult<Option<Transaction>> {
        let _ = (address, nonce);
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Returns the receipt of a transaction by transaction hash.
    async fn transaction_receipt(
        &self, hash: H256,
    ) -> RpcResult<Option<Receipt>> {
        self.transaction_receipt(hash).map_err(Into::into)
    }

    /// Returns the balance of the account of given address.
    async fn balance(
        &self, address: Address, block_number: Option<BlockId>,
    ) -> RpcResult<U256> {
        self.user_balance(address, block_number).map_err(Into::into)
    }

    /// Returns the value from a storage position at a given address
    async fn storage_at(
        &self, address: Address, index: JsonStorageKey,
        block_number: Option<BlockId>,
    ) -> RpcResult<H256> {
        self.storage_at(address, index, block_number)
            .map_err(Into::into)
    }

    /// Returns the number of transactions sent from an address at given block
    /// number.
    async fn transaction_count(
        &self, address: Address, block_number: Option<BlockId>,
    ) -> RpcResult<U256> {
        self.next_nonce(address, block_number).map_err(Into::into)
    }

    /// Returns code at a given address at given block number.
    async fn get_code(
        &self, address: Address, block_number: Option<BlockId>,
    ) -> RpcResult<Bytes> {
        self.code_at(address, block_number).map_err(Into::into)
    }

    /// Returns the block's header at given number.
    async fn header_by_number(
        &self, hash: BlockNumberOrTag,
    ) -> RpcResult<Option<Header>> {
        let _ = hash;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Returns the block's header at given hash.
    async fn header_by_hash(&self, hash: H256) -> RpcResult<Option<Header>> {
        let _ = hash;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// `eth_simulateV1` executes an arbitrary number of transactions on top of
    /// the requested state. The transactions are packed into individual
    /// blocks. Overrides can be provided.
    async fn simulate_v1(
        &self, payload: SimulatePayload, block_id: Option<BlockId>,
    ) -> RpcResult<Vec<SimulatedBlock<Block>>> {
        self.simulate_v1(payload, block_id).map_err(Into::into)
    }

    /// Executes a new message call immediately without creating a transaction
    /// on the block chain.
    async fn call(
        &self, request: TransactionRequest, block_number: Option<BlockId>,
        state_overrides: Option<RpcStateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> RpcResult<Bytes> {
        let (execution, _estimation) = self.tx_executor.exec_transaction(
            request,
            block_number,
            state_overrides,
            block_overrides,
        )?;

        Ok(execution.output.into())
    }

    /// Simulate arbitrary number of transactions at an arbitrary blockchain
    /// index, with the optionality of state overrides
    async fn call_many(
        &self, bundle: Bundle, state_context: Option<StateContext>,
        state_override: Option<RpcStateOverride>,
    ) -> RpcResult<Vec<EthCallResponse>> {
        let _ = bundle;
        let _ = state_context;
        let _ = state_override;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Generates an access list for a transaction.
    ///
    /// This method creates an [EIP2930](https://eips.ethereum.org/EIPS/eip-2930) type accessList based on a given Transaction.
    ///
    /// An access list contains all storage slots and addresses touched by the
    /// transaction, except for the sender account and the chain's
    /// precompiles.
    ///
    /// It returns list of addresses and storage keys used by the transaction,
    /// plus the gas consumed when the access list is added. That is, it
    /// gives you the list of addresses and storage keys that will be used
    /// by that transaction, plus the gas consumed if the access
    /// list is included. Like eth_estimateGas, this is an estimation; the list
    /// could change when the transaction is actually mined. Adding an
    /// accessList to your transaction does not necessary result in lower
    /// gas usage compared to a transaction without an access list.
    async fn create_access_list(
        &self, request: TransactionRequest, block_number: Option<BlockId>,
    ) -> RpcResult<AccessListResult> {
        let _ = block_number;
        let _ = request;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Generates and returns an estimate of how much gas is necessary to allow
    /// the transaction to complete.
    async fn estimate_gas(
        &self, request: TransactionRequest, block_number: Option<BlockId>,
        state_overrides: Option<RpcStateOverride>,
    ) -> RpcResult<U256> {
        let (_, estimated_gas) = self.tx_executor.exec_transaction(
            request,
            block_number,
            state_overrides,
            None,
        )?;

        Ok(estimated_gas)
    }

    /// Returns the current price per gas in wei.
    async fn gas_price(&self) -> RpcResult<U256> { Ok(self.gas_price()) }

    /// Returns the account details by specifying an address and a block
    /// number/tag
    // async fn get_account(
    //     &self,
    //     address: Address,
    //     block: BlockId,
    // ) -> RpcResult<Option<reth_rpc_types::Account>>;

    /// Introduced in EIP-1559, returns suggestion for the priority for dynamic
    /// fee transactions.
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        self.max_priority_fee_per_gas().map_err(Into::into)
    }

    /// Introduced in EIP-4844, returns the current blob base fee in wei.
    // async fn blob_base_fee(&self) -> RpcResult<U256>;

    /// Returns the Transaction fee history
    ///
    /// Introduced in EIP-1559 for getting information on the appropriate
    /// priority fee to use.
    ///
    /// Returns transaction base fee per gas and effective priority fee per gas
    /// for the requested/supported block range. The returned Fee history
    /// for the returned block range can be a subsection of the requested
    /// range if not all blocks are available.
    async fn fee_history(
        &self, block_count: U64, newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        self.fee_history(
            block_count.as_u64().into(),
            newest_block,
            reward_percentiles,
        )
        .map_err(Into::into)
    }

    /// Returns whether the client is actively mining new blocks.
    async fn is_mining(&self) -> RpcResult<bool> { Ok(false) }

    /// Returns the number of hashes per second that the node is mining with.
    async fn hashrate(&self) -> RpcResult<U256> { Ok(U256::zero()) }

    /// Returns the hash of the current block, the seedHash, and the boundary
    /// condition to be met (“target”)
    // async fn get_work(&self) -> RpcResult<Work>;

    /// Used for submitting mining hashrate.
    ///
    /// Can be used for remote miners to submit their hash rate.
    /// It accepts the miner hash rate and an identifier which must be unique
    /// between nodes. Returns `true` if the block was successfully
    /// submitted, `false` otherwise.
    async fn submit_hashrate(
        &self, hashrate: U256, id: H256,
    ) -> RpcResult<bool> {
        let _ = (hashrate, id);
        Ok(false)
    }

    /// Used for submitting a proof-of-work solution.
    async fn submit_work(
        &self, nonce: H64, pow_hash: H256, mix_digest: H256,
    ) -> RpcResult<bool> {
        let _ = (nonce, pow_hash, mix_digest);
        Ok(false)
    }

    /// Sends transaction; will block waiting for signer to return the
    /// transaction hash.
    async fn send_transaction(
        &self, request: TransactionRequest,
    ) -> RpcResult<H256> {
        let _ = request;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Sends signed transaction, returning its hash.
    async fn send_raw_transaction(&self, bytes: Bytes) -> RpcResult<H256> {
        let tx = if let Ok(tx) =
            TransactionWithSignature::from_raw(&bytes.into_vec())
        {
            tx
        } else {
            bail!(EthApiError::FailedToDecodeSignedTransaction)
        };

        if tx.space() != Space::Ethereum {
            bail!(EthApiError::Other(
                "Incorrect transaction space".to_string()
            ));
        }

        if tx.recover_public().is_err() {
            bail!(EthApiError::InvalidTransactionSignature);
        }

        let r = self.send_transaction_with_signature(tx)?;
        Ok(r)
    }

    async fn submit_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        self.send_raw_transaction(raw).await
    }

    /// Returns an Ethereum specific signature with:
    /// sign(keccak256("\x19Ethereum Signed Message:\n"
    /// + len(message) + message))).
    async fn sign(&self, address: Address, message: Bytes) -> RpcResult<Bytes> {
        let _ = (address, message);
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    /// Signs a transaction that can be submitted to the network at a later time
    /// using with `sendRawTransaction.`
    async fn sign_transaction(
        &self, transaction: TransactionRequest,
    ) -> RpcResult<Bytes> {
        let _ = transaction;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    async fn logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        self.logs(filter).map_err(|err| err.into())
    }

    async fn account_pending_transactions(
        &self, address: Address, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        self.account_pending_transactions(
            address,
            maybe_start_nonce,
            maybe_limit,
        )
        .map_err(Into::into)
    }
}
