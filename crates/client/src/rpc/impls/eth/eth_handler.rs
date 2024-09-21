// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    errors::{
        geth_call_execution_error, internal_error, invalid_input_rpc_err,
        invalid_params, request_rejected_in_catch_up_mode, unknown_block,
        EthApiError, RpcInvalidTransactionError, RpcPoolError,
    },
    helpers::{FeeHistoryCache, MAX_FEE_HISTORY_CACHE_BLOCK_COUNT},
    impls::RpcImplConfiguration,
    traits::eth_space::eth::Eth,
    types::{
        eth::{
            AccountPendingTransactions, Block as RpcBlock, BlockNumber,
            EthRpcLogFilter, Log, Receipt, SyncInfo, SyncStatus, Transaction,
            TransactionRequest,
        },
        Bytes, FeeHistory, Index, U64 as HexU64,
    },
};
use cfx_execute_helper::estimation::EstimateRequest;
use cfx_executor::executive::{
    string_revert_reason_decode, Executed, ExecutionError, ExecutionOutcome,
    TxDropError,
};
use cfx_parameters::rpc::GAS_PRICE_DEFAULT_VALUE;
use cfx_rpc_cfx_types::{traits::BlockProvider, PhantomBlock};
use cfx_statedb::StateDbExt;
use cfx_types::{
    Address, AddressSpaceUtil, BigEndianHash, Space, H160, H256, U256, U64,
};
use cfx_vm_types::Error as VmError;
use cfxcore::{
    errors::{Error as CfxRpcError, Result as CfxRpcResult},
    ConsensusGraph, ConsensusGraphTrait, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use clap::crate_version;
use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use primitives::{
    filter::LogFilter, receipt::EVM_SPACE_SUCCESS, Action,
    BlockHashOrEpochNumber, EpochNumber, StorageKey, StorageValue,
    TransactionStatus, TransactionWithSignature,
};
use rustc_hex::ToHex;
use std::convert::TryInto;

pub struct EthHandler {
    config: RpcImplConfiguration,
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    fee_history_cache: FeeHistoryCache,
}

impl EthHandler {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
    ) -> Self {
        EthHandler {
            config,
            consensus,
            sync,
            tx_pool,
            fee_history_cache: FeeHistoryCache::new(),
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    pub fn fetch_block_by_height(
        &self, height: u64,
    ) -> Result<PhantomBlock, String> {
        let maybe_block = self.consensus_graph().get_phantom_block_by_number(
            EpochNumber::Number(height),
            None,
            false,
        )?;
        if let Some(block) = maybe_block {
            Ok(block)
        } else {
            Err("Specified block header does not exist".into())
        }
    }

    pub fn fetch_block_by_hash(
        &self, hash: &H256,
    ) -> Result<PhantomBlock, String> {
        let maybe_block = self
            .consensus_graph()
            .get_phantom_block_by_hash(hash, false)?;
        if let Some(block) = maybe_block {
            Ok(block)
        } else {
            Err("Specified block header does not exist".into())
        }
    }

    fn exec_transaction(
        &self, mut request: TransactionRequest,
        block_number_or_hash: Option<BlockNumber>,
    ) -> CfxRpcResult<(Executed, U256)> {
        let consensus_graph = self.consensus_graph();

        if request.gas_price.is_some()
            && request.max_priority_fee_per_gas.is_some()
        {
            return Err(RpcError::from(
                EthApiError::ConflictingFeeFieldsInRequest,
            )
            .into());
        }

        if request.max_fee_per_gas.is_some()
            && request.max_priority_fee_per_gas.is_some()
        {
            if request.max_fee_per_gas.unwrap()
                < request.max_priority_fee_per_gas.unwrap()
            {
                return Err(RpcError::from(
                    RpcInvalidTransactionError::TipAboveFeeCap,
                )
                .into());
            }
        }

        let epoch = match block_number_or_hash.unwrap_or_default() {
            BlockNumber::Hash { hash, .. } => {
                match consensus_graph.get_block_epoch_number(&hash) {
                    Some(e) => {
                        // do not expose non-pivot blocks in eth RPC
                        let pivot = consensus_graph
                            .get_block_hashes_by_epoch(EpochNumber::Number(e))?
                            .last()
                            .cloned();

                        if Some(hash) != pivot {
                            bail!("Block {:?} not found", hash);
                        }

                        EpochNumber::Number(e)
                    }
                    None => bail!("Block {:?} not found", hash),
                }
            }
            epoch => epoch.try_into()?,
        };

        // if gas_price is zero, it is considered as not set
        request.unset_zero_gas_price();

        let estimate_request = EstimateRequest {
            has_sender: request.from.is_some(),
            has_gas_limit: request.gas.is_some(),
            has_gas_price: request.has_gas_price(),
            has_nonce: request.nonce.is_some(),
            has_storage_limit: false,
        };

        let chain_id = self.consensus.best_chain_id();

        let max_gas = self.config.max_estimation_gas_limit;
        let signed_tx = request.sign_call(chain_id.in_evm_space(), max_gas)?;

        trace!("call tx {:?}, request {:?}", signed_tx, estimate_request);
        let (execution_outcome, estimation) = consensus_graph.call_virtual(
            &signed_tx,
            epoch,
            estimate_request,
        )?;

        let executed = match execution_outcome {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                expected,
                got,
            )) => bail!(invalid_input_rpc_err(
                format! {"nonce is too old expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::InvalidRecipientAddress(recipient),
            ) => bail!(invalid_input_rpc_err(
                format! {"invalid recipient address {:?}", recipient}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit { expected, got },
            ) => bail!(invalid_input_rpc_err(
                format! {"not enough gas limit with respected to tx size: expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(invalid_input_rpc_err(format! {"err: {:?}", e}))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                e @ ExecutionError::NotEnoughCash { .. },
                _executed,
            ) => {
                bail!(geth_call_execution_error(
                    format!(
                        "insufficient funds for gas * price + value: {:?})",
                        e
                    ),
                    "".into()
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(VmError::Reverted),
                executed,
            ) => bail!(geth_call_execution_error(
                format!(
                    "execution reverted: revert: {}",
                    string_revert_reason_decode(&executed.output)
                ),
                format!("0x{}", executed.output.to_hex::<String>())
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(e),
                _executed,
            ) => bail!(geth_call_execution_error(
                format!("execution reverted: {}", e),
                "".into()
            )),
            ExecutionOutcome::Finished(executed) => executed,
        };

        Ok((executed, estimation.estimated_gas_limit))
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> CfxRpcResult<H256> {
        if self.sync.catch_up_mode() {
            warn!("Ignore send_transaction request {}. Cannot send transaction when the node is still in catch-up mode.", tx.hash());
            bail!(request_rejected_in_catch_up_mode(None));
        }
        let (signed_trans, failed_trans) =
            self.tx_pool.insert_new_transactions(vec![tx]);
        if signed_trans.len() + failed_trans.len() > 1 {
            // This should never happen
            error!("insert_new_transactions failed, invalid length of returned result vector {}", signed_trans.len() + failed_trans.len());
            Ok(H256::zero().into())
        } else if signed_trans.len() + failed_trans.len() == 0 {
            // For tx in transactions_pubkey_cache, we simply ignore them
            debug!("insert_new_transactions ignores inserted transactions");
            bail!(RpcError::from(EthApiError::PoolError(
                RpcPoolError::ReplaceUnderpriced
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

    fn construct_rpc_receipt(
        &self, b: &PhantomBlock, idx: usize, prior_log_index: &mut usize,
    ) -> RpcResult<Receipt> {
        if b.transactions.len() != b.receipts.len() {
            return Err(internal_error(
                "Inconsistent state: transactions and receipts length mismatch",
            ));
        }

        if b.transactions.len() != b.errors.len() {
            return Err(internal_error(
                "Inconsistent state: transactions and errors length mismatch",
            ));
        }

        if idx >= b.transactions.len() {
            return Err(internal_error(
                "Inconsistent state: tx index out of bound",
            ));
        }

        let tx = &b.transactions[idx];
        let receipt = &b.receipts[idx];

        if receipt.logs.iter().any(|l| l.space != Space::Ethereum) {
            return Err(internal_error(
                "Inconsistent state: native tx in phantom block",
            ));
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
                address: log.address,
                topics: log.topics,
                data: Bytes(log.data),
                block_hash,
                block_number: block_height,
                transaction_hash,
                transaction_index,
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
                Action::Call(addr) => Some(*addr),
            },
            block_number: block_height,
            cumulative_gas_used: receipt.accumulated_gas_used,
            gas_used,
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

    fn get_tx_from_txpool(&self, hash: H256) -> Option<Transaction> {
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

    fn get_block_receipts(
        &self, block_num: BlockNumber,
    ) -> RpcResult<Vec<Receipt>> {
        let b = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            let phantom_block = match block_num {
                BlockNumber::Hash { hash, .. } => self
                    .consensus_graph()
                    .get_phantom_block_by_hash(
                        &hash, false, /* include_traces */
                    )
                    .map_err(RpcError::invalid_params)?,
                _ => self
                    .consensus_graph()
                    .get_phantom_block_by_number(
                        block_num.try_into()?,
                        None,
                        false, /* include_traces */
                    )
                    .map_err(RpcError::invalid_params)?,
            };

            match phantom_block {
                None => return Err(unknown_block()),
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

    fn block_tx_by_index(
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
}

impl BlockProvider for &EthHandler {
    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.consensus_graph().get_block_epoch_number(hash)
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.consensus_graph()
            .get_block_hashes_by_epoch(epoch_number)
    }
}

impl Eth for EthHandler {
    fn client_version(&self) -> RpcResult<String> {
        debug!("RPC Request: web3_clientVersion()");
        Ok(parity_version::version(crate_version!()))
    }

    fn net_version(&self) -> RpcResult<String> {
        debug!("RPC Request: net_version()");
        Ok(format!("{}", self.consensus.best_chain_id().in_evm_space()))
    }

    fn protocol_version(&self) -> RpcResult<String> {
        debug!("RPC Request: eth_protocolVersion()");
        // 65 is a common ETH version now
        Ok(format!("{}", 65))
    }

    fn syncing(&self) -> RpcResult<SyncStatus> {
        debug!("RPC Request: eth_syncing()");
        if self.sync.catch_up_mode() {
            Ok(
                // Now pass some statistics of Conflux just to make the
                // interface happy
                SyncStatus::Info(SyncInfo {
                    starting_block: U256::from(self.consensus.block_count()),
                    current_block: U256::from(self.consensus.block_count()),
                    highest_block: U256::from(
                        self.sync.get_synchronization_graph().block_count(),
                    ),
                    warp_chunks_amount: None,
                    warp_chunks_processed: None,
                }),
            )
        } else {
            Ok(SyncStatus::None)
        }
    }

    fn hashrate(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_hashrate()");
        // We do not mine
        Ok(U256::zero())
    }

    fn author(&self) -> RpcResult<H160> {
        debug!("RPC Request: eth_coinbase()");
        // We do not care this, just return zero address
        Ok(H160::zero())
    }

    fn is_mining(&self) -> RpcResult<bool> {
        debug!("RPC Request: eth_mining()");
        // We do not mine from ETH perspective
        Ok(false)
    }

    fn chain_id(&self) -> RpcResult<Option<U64>> {
        debug!("RPC Request: eth_chainId()");
        return Ok(Some(self.consensus.best_chain_id().in_evm_space().into()));
    }

    fn gas_price(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_gasPrice()");
        let (_, maybe_base_price) =
            self.tx_pool.get_best_info_with_parent_base_price();
        if let Some(base_price) = maybe_base_price {
            return Ok(base_price[Space::Ethereum]);
        }

        let consensus_gas_price = self
            .consensus_graph()
            .gas_price(Space::Ethereum)
            .unwrap_or(GAS_PRICE_DEFAULT_VALUE.into());
        Ok(std::cmp::max(
            consensus_gas_price,
            self.tx_pool.config.min_eth_tx_price.into(),
        ))
    }

    fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_maxPriorityFeePerGas()");
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

    fn accounts(&self) -> RpcResult<Vec<H160>> {
        debug!("RPC Request: eth_accounts()");
        // Conflux eSpace does not manage accounts
        Ok(vec![])
    }

    fn block_number(&self) -> RpcResult<U256> {
        debug!("RPC Request: eth_blockNumber()");

        let consensus_graph = self.consensus_graph();
        let epoch_num = EpochNumber::LatestState;
        match consensus_graph.get_height_from_epoch_number(epoch_num.into()) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn balance(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = num.unwrap_or_default().try_into()?;
        debug!(
            "RPC Request: eth_getBalance(address={:?}, epoch_num={:?})",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&address.with_evm_space())
            .map_err(|err| CfxRpcError::from(err))?;

        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    fn storage_at(
        &self, address: H160, position: U256, block_num: Option<BlockNumber>,
    ) -> RpcResult<H256> {
        let epoch_num = block_num.unwrap_or_default().try_into()?;
        debug!(
            "RPC Request: eth_getStorageAt(address={:?}, position={:?}, block_num={:?})",
            address, position, epoch_num
        );

        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "epoch_number")?;

        let position: H256 = H256::from_uint(&position);

        let key = StorageKey::new_storage_key(&address, position.as_ref())
            .with_evm_space();

        Ok(
            match state_db
                .get::<StorageValue>(key)
                .map_err(|err| CfxRpcError::from(err))?
            {
                Some(entry) => H256::from_uint(&entry.value).into(),
                None => H256::zero(),
            },
        )
    }

    fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!(
            "RPC Request: eth_getBlockByHash(hash={:?}, include_txs={:?})",
            hash, include_txs
        );

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_hash(
                    &hash, false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(RpcBlock::from_phantom(&pb, include_txs))),
        }
    }

    fn block_by_number(
        &self, block_num: BlockNumber, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!("RPC Request: eth_getBlockByNumber(block_number={:?}, include_txs={:?})", block_num, include_txs);

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_number(
                    block_num.try_into()?,
                    None,
                    false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(RpcBlock::from_phantom(&pb, include_txs))),
        }
    }

    fn transaction_count(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> RpcResult<U256> {
        debug!(
            "RPC Request: eth_getTransactionCount(address={:?}, block_number={:?})",
            address, num
        );

        let nonce = match num {
            Some(BlockNumber::Pending) => {
                self.tx_pool.get_next_nonce(&address.with_evm_space())
            }
            _ => {
                let num = num.unwrap_or_default().try_into()?;

                self.consensus_graph().next_nonce(
                    address.with_evm_space(),
                    BlockHashOrEpochNumber::EpochNumber(num),
                    "num",
                )?
            }
        };

        Ok(nonce)
    }

    fn block_transaction_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getBlockTransactionCountByHash(hash={:?})",
            hash,
        );

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_hash(
                    &hash, false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(pb.transactions.len().into())),
        }
    }

    fn block_transaction_count_by_number(
        &self, block_num: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getBlockTransactionCountByNumber(block_number={:?})",
            block_num
        );

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_number(
                    block_num.try_into()?,
                    None,
                    false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        match phantom_block {
            None => Ok(None),
            Some(pb) => Ok(Some(pb.transactions.len().into())),
        }
    }

    fn block_uncles_count_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<U256>> {
        debug!("RPC Request: eth_getUncleCountByBlockHash(hash={:?})", hash);

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

    fn block_uncles_count_by_number(
        &self, block_num: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        debug!(
            "RPC Request: eth_getUncleCountByBlockNumber(block_number={:?})",
            block_num
        );

        let maybe_epoch = self
            .consensus
            .get_block_hashes_by_epoch(block_num.try_into()?)
            .ok();

        Ok(maybe_epoch.map(|_| 0.into()))
    }

    fn code_at(
        &self, address: H160, epoch_num: Option<BlockNumber>,
    ) -> RpcResult<Bytes> {
        let epoch_num = epoch_num.unwrap_or_default().try_into()?;

        debug!(
            "RPC Request: eth_getCode(address={:?}, epoch_num={:?})",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_eth_state_db_by_epoch_number(epoch_num, "num")?;

        let address = address.with_evm_space();

        let code = match state_db
            .get_account(&address)
            .map_err(|err| CfxRpcError::from(err))?
        {
            Some(acc) => match state_db
                .get_code(&address, &acc.code_hash)
                .map_err(|err| CfxRpcError::from(err))?
            {
                Some(code) => (*code.code).clone(),
                _ => vec![],
            },
            None => vec![],
        };

        Ok(Bytes::new(code))
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        debug!("RPC Request: eth_sendRawTransaction(raw={:?})", raw,);
        let tx = if let Ok(tx) =
            TransactionWithSignature::from_raw(&raw.into_vec())
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

    fn submit_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        self.send_raw_transaction(raw)
    }

    fn call(
        &self, request: TransactionRequest,
        block_number_or_hash: Option<BlockNumber>,
    ) -> RpcResult<Bytes> {
        debug!(
            "RPC Request: eth_call(request={:?}, block_num={:?})",
            request, block_number_or_hash
        );

        let (execution, _estimation) =
            self.exec_transaction(request, block_number_or_hash)?;

        Ok(execution.output.into())
    }

    fn estimate_gas(
        &self, request: TransactionRequest,
        block_number_or_hash: Option<BlockNumber>,
    ) -> RpcResult<U256> {
        debug!(
            "RPC Request: eth_estimateGas(request={:?}, block_num={:?})",
            request, block_number_or_hash
        );
        let (_, estimated_gas) =
            self.exec_transaction(request, block_number_or_hash)?;

        Ok(estimated_gas)
    }

    fn fee_history(
        &self, mut block_count: HexU64, newest_block: BlockNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        debug!(
            "RPC Request: eth_feeHistory(block_count={}, newest_block={:?}, reward_percentiles={:?})",
            block_count, newest_block, reward_percentiles
        );

        if block_count.as_u64() == 0 || newest_block == BlockNumber::Pending {
            return Ok(FeeHistory::new());
        }

        if block_count.as_u64() > MAX_FEE_HISTORY_CACHE_BLOCK_COUNT {
            block_count = HexU64::from(MAX_FEE_HISTORY_CACHE_BLOCK_COUNT);
        }

        if let Some(percentiles) = &reward_percentiles {
            if percentiles.windows(2).any(|w| w[0] > w[1] || w[0] > 100.) {
                return Err(EthApiError::InvalidRewardPercentiles.into());
            }
        }
        let reward_percentiles = reward_percentiles.unwrap_or_default();

        // keep read lock to ensure consistent view
        let _consensus = self.consensus_graph().inner.read();

        let newest_height: u64 = self
            .consensus_graph()
            .get_height_from_epoch_number(newest_block.clone().try_into()?)
            .map_err(RpcError::invalid_params)?;

        if newest_block == BlockNumber::Latest {
            let fetch_block_by_hash =
                |height| self.fetch_block_by_hash(&height);

            let latest_block = self
                .fetch_block_by_height(newest_height)
                .map_err(RpcError::invalid_params)?;

            self.fee_history_cache
                .update_to_latest_block(
                    newest_height,
                    latest_block.pivot_header.hash(),
                    block_count.as_u64(),
                    fetch_block_by_hash,
                )
                .map_err(RpcError::invalid_params)?;
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

        let block = self
            .fetch_block_by_height(end_block + 1)
            .map_err(RpcError::invalid_params)?;

        fee_history.finish(
            start_block,
            block.pivot_header.base_price().as_ref(),
            Space::Ethereum,
        );

        Ok(fee_history)
    }

    fn transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByHash(hash={:?})", hash);

        let tx_index = match self
            .consensus
            .get_data_manager()
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

    fn transaction_by_block_hash_and_index(
        &self, hash: H256, idx: Index,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByBlockHashAndIndex(hash={:?}, idx={:?})", hash, idx);

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_hash(
                    &hash, false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        Ok(Self::block_tx_by_index(phantom_block, idx.value()))
    }

    fn transaction_by_block_number_and_index(
        &self, block_num: BlockNumber, idx: Index,
    ) -> RpcResult<Option<Transaction>> {
        debug!("RPC Request: eth_getTransactionByBlockNumberAndIndex(block_num={:?}, idx={:?})", block_num, idx);

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();

            self.consensus_graph()
                .get_phantom_block_by_number(
                    block_num.try_into()?,
                    None,
                    false, /* include_traces */
                )
                .map_err(RpcError::invalid_params)?
        };

        Ok(Self::block_tx_by_index(phantom_block, idx.value()))
    }

    fn transaction_receipt(&self, tx_hash: H256) -> RpcResult<Option<Receipt>> {
        debug!(
            "RPC Request: eth_getTransactionReceipt(tx_hash={:?})",
            tx_hash
        );

        let tx_index =
            match self.consensus.get_data_manager().transaction_index_by_hash(
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

            // if the if-branch was not entered, we do the bookeeping here
            prior_log_index += phantom_block.receipts[idx].logs.len();
        }

        Ok(None)
    }

    fn uncle_by_block_hash_and_index(
        &self, hash: H256, idx: Index,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!(
            "RPC Request: eth_getUncleByBlockHashAndIndex(hash={:?}, idx={:?})",
            hash, idx
        );
        // We do not have uncle block
        Ok(None)
    }

    fn uncle_by_block_number_and_index(
        &self, block_num: BlockNumber, idx: Index,
    ) -> RpcResult<Option<RpcBlock>> {
        debug!("RPC Request: eth_getUncleByBlockNumberAndIndex(block_num={:?}, idx={:?})", block_num, idx);
        // We do not have uncle block
        Ok(None)
    }

    fn logs(&self, filter: EthRpcLogFilter) -> RpcResult<Vec<Log>> {
        debug!("RPC Request: eth_getLogs(filter={:?})", filter);

        let filter: LogFilter = filter.into_primitive(self)?;

        let logs = self
            .consensus_graph()
            .logs(filter)
            .map_err(|err| CfxRpcError::from(err))?;

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

    fn submit_hashrate(&self, _: U256, _: H256) -> RpcResult<bool> {
        debug!("RPC Request: eth_submitHashrate()");
        // We do not care mining
        Ok(false)
    }

    fn eth_block_receipts(
        &self, block: BlockNumber,
    ) -> RpcResult<Vec<Receipt>> {
        debug!(
            "RPC Request: eth_getBlockReceipts(block_number={:?})",
            block
        );

        self.get_block_receipts(block)
    }

    fn block_receipts(
        &self, block_num: Option<BlockNumber>,
    ) -> RpcResult<Vec<Receipt>> {
        debug!(
            "RPC Request: parity_getBlockReceipts(block_number={:?})",
            block_num
        );

        let block_num = block_num.unwrap_or_default();

        self.get_block_receipts(block_num)
    }

    fn account_pending_transactions(
        &self, address: H160, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        debug!("RPC Request: eth_getAccountPendingTransactions(addr={:?}, start_nonce={:?}, limit={:?})",
              address, maybe_start_nonce, maybe_limit);

        let (pending_txs, tx_status, pending_count) = self
            .tx_pool
            .get_account_pending_transactions(
                &Address::from(address).with_evm_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.consensus.best_epoch_number(),
            )
            .map_err(|e| internal_error(e))?;
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
}
