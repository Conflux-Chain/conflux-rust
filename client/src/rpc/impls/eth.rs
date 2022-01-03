// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::cmp::min;

use cfx_statedb::StateDbExt;
use jsonrpc_core::{BoxFuture, Result as RpcResult};
use rlp::Rlp;

use cfx_types::{
    Address, AddressSpaceUtil, BigEndianHash, Space, H160, H256, U256, U64,
};
use cfxcore::{
    executive::{
        revert_reason_decode, ExecutionError, ExecutionOutcome, TxDropError,
    },
    rpc_errors::{
        invalid_params_check, Error as CfxRpcError, Result as CfxRpcResult,
    },
    trace::ErrorUnwind,
    vm, ConsensusGraph, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use primitives::{
    Action, Eip155Transaction, EpochNumber as BlockNumber, SignedTransaction,
    StorageKey, StorageValue, TransactionIndex, TransactionWithSignature,
};

use crate::rpc::{
    error_codes::{
        call_execution_error, invalid_params, request_rejected_in_catch_up_mode,
    },
    impls::cfx::BlockExecInfo,
    traits::eth::{Eth, EthFilter},
    types::{
        eth::{
            CallRequest, Filter, FilterChanges, Log, Receipt, RichBlock,
            SyncInfo, SyncStatus, Transaction,
        },
        Bytes, Index, MAX_GAS_CALL_REQUEST,
    },
};

pub struct EthHandler {
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
}

impl EthHandler {
    pub fn new(
        consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        tx_pool: SharedTransactionPool,
    ) -> Self
    {
        EthHandler {
            consensus,
            sync,
            tx_pool,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }
}

pub fn sign_call(
    chain_id: u32, request: CallRequest,
) -> RpcResult<SignedTransaction> {
    let max_gas = U256::from(MAX_GAS_CALL_REQUEST);
    let gas = min(request.gas.unwrap_or(max_gas), max_gas);
    let from = request.from.unwrap_or_else(|| Address::random());

    Ok(Eip155Transaction {
        nonce: request.nonce.unwrap_or_default(),
        action: request.to.map_or(Action::Create, |addr| Action::Call(addr)),
        gas,
        gas_price: request.gas_price.unwrap_or(1.into()),
        value: request.value.unwrap_or_default(),
        chain_id,
        data: request.data.unwrap_or_default().into_vec(),
    }
    .fake_sign(from.with_evm_space()))
}

impl EthHandler {
    fn exec_transaction(
        &self, request: CallRequest, epoch: Option<BlockNumber>,
    ) -> CfxRpcResult<ExecutionOutcome> {
        let consensus_graph = self.consensus_graph();
        let epoch = epoch.unwrap_or(BlockNumber::LatestState);

        let chain_id = self.consensus.best_chain_id();
        let signed_tx = sign_call(chain_id.in_evm_space(), request)?;
        trace!("call tx {:?}", signed_tx);
        consensus_graph.call_virtual(&signed_tx, epoch.into())
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
        // FIXME: how is it possible?
        if signed_trans.len() + failed_trans.len() > 1 {
            // This should never happen
            error!("insert_new_transactions failed, invalid length of returned result vector {}", signed_trans.len() + failed_trans.len());
            Ok(H256::zero().into())
        } else if signed_trans.len() + failed_trans.len() == 0 {
            // For tx in transactions_pubkey_cache, we simply ignore them
            debug!("insert_new_transactions ignores inserted transactions");
            // FIXME: this is not invalid params
            bail!(invalid_params("tx", String::from("tx already exist")))
        } else if signed_trans.is_empty() {
            let tx_err = failed_trans.iter().next().expect("Not empty").1;
            // FIXME: this is not invalid params
            bail!(invalid_params("tx", tx_err))
        } else {
            let tx_hash = signed_trans[0].hash();
            self.sync.append_received_transactions(signed_trans);
            Ok(tx_hash.into())
        }
    }

    fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> CfxRpcResult<Option<BlockExecInfo>> {
        let consensus_graph = self.consensus_graph();

        let (pivot_hash, block_receipts, maybe_state_root) =
            match consensus_graph.get_block_execution_info(block_hash) {
                None => return Ok(None),
                Some((exec_res, maybe_state_root)) => {
                    (exec_res.0, exec_res.1.block_receipts, maybe_state_root)
                }
            };

        let epoch_number = self
            .consensus
            .get_data_manager()
            .block_header_by_hash(&pivot_hash)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?
            .height();

        if epoch_number > consensus_graph.best_executed_state_epoch_number() {
            // The receipt is only visible to optimistic execution.
            return Ok(None);
        }

        let block = self
            .consensus
            .get_data_manager()
            .block_by_hash(&block_hash, false /* update_cache */)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?;

        if block_receipts.receipts.len() != block.transactions.len() {
            bail!("Inconsistent state");
        }

        Ok(Some(BlockExecInfo {
            block_receipts,
            block,
            epoch_number,
            maybe_state_root,
            pivot_hash,
        }))
    }

    fn construct_rpc_receipt(
        &self, tx_index: TransactionIndex, exec_info: &BlockExecInfo,
    ) -> CfxRpcResult<Receipt> {
        let id = tx_index.index;

        if id >= exec_info.block.transactions.len()
            || id >= exec_info.block_receipts.receipts.len()
            || id >= exec_info.block_receipts.tx_execution_error_messages.len()
        {
            bail!("Inconsistent state");
        }

        let _prior_gas_used = match id {
            0 => U256::zero(),
            id => {
                exec_info.block_receipts.receipts[id - 1].accumulated_gas_used
            }
        };

        let tx = &exec_info.block.transactions[id];
        let inner = &exec_info.block_receipts.receipts[id];

        let receipt = Receipt {
            transaction_type: None, //TODO: how is it defined?
            transaction_hash: Some(tx.hash().clone()),
            transaction_index: Some(tx_index.index.into()), /* TODO: Compute
                                                             * a correct index,
                                                             */
            block_hash: Some(exec_info.pivot_hash),
            from: Some(tx.sender().address),
            to: match tx.action() {
                Action::Create => None,
                Action::Call(addr) => Some(*addr),
            },
            block_number: Some(exec_info.epoch_number.into()),
            cumulative_gas_used: inner.accumulated_gas_used,
            gas_used: None, /* TODO: compute gas used. The acutal use or
                             * charged? */
            contract_address: None, // TODO: compute contract address by tx.
            logs: inner.logs.iter().map(|_| todo!()).collect(), /* TODO: log mapping */
            state_root: exec_info.maybe_state_root.clone(),
            logs_bloom: inner.log_bloom,
            status_code: None, // TODO: make sure what it is.
            effective_gas_price: *tx.gas_price(), /* TODO: what it is, is it
                                * after cip-1559? */
        };

        Ok(receipt)
    }
}

impl Eth for EthHandler {
    type Metadata = ();

    fn protocol_version(&self) -> jsonrpc_core::Result<String> {
        // 65 is a common ETH version now
        Ok(format!("{}", 65))
    }

    fn syncing(&self) -> jsonrpc_core::Result<SyncStatus> {
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

    fn hashrate(&self) -> jsonrpc_core::Result<U256> {
        // We do not mine
        Ok(U256::zero())
    }

    fn author(&self) -> jsonrpc_core::Result<H160> {
        // We do not care this, just return zero address
        Ok(H160::zero())
    }

    fn is_mining(&self) -> jsonrpc_core::Result<bool> {
        // We do not mine from ETH perspective
        Ok(false)
    }

    fn chain_id(&self) -> jsonrpc_core::Result<Option<U64>> {
        return Ok(Some(
            self.consensus.best_chain_id().in_native_space().into(),
        ));
    }

    fn gas_price(&self) -> BoxFuture<U256> { todo!() }

    fn max_priority_fee_per_gas(&self) -> BoxFuture<U256> { todo!() }

    fn accounts(&self) -> jsonrpc_core::Result<Vec<H160>> { todo!() }

    fn block_number(&self) -> jsonrpc_core::Result<U256> {
        let consensus_graph = self.consensus_graph();
        let epoch_num = BlockNumber::LatestMined;
        info!("RPC Request: eth_blockNumber()");
        match consensus_graph.get_height_from_epoch_number(epoch_num.into()) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(jsonrpc_core::Error::invalid_params(e)),
        }
    }

    fn balance(
        &self, address: H160, num: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<U256> {
        let epoch_num = num.unwrap_or(BlockNumber::LatestState).into();

        info!(
            "RPC Request: eth_getBalance address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&address.with_evm_space())
            .map_err(|err| CfxRpcError::from(err))?;

        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    fn storage_at(
        &self, address: H160, position: U256, epoch_num: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<H256> {
        let epoch_num = epoch_num.unwrap_or(BlockNumber::LatestState).into();

        info!(
            "RPC Request: eth_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            address, position, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_number")?;

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

    fn block_by_hash(&self, _: H256, _: bool) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn block_by_number(
        &self, _: BlockNumber, _: bool,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn transaction_count(
        &self, _: H160, _: Option<BlockNumber>,
    ) -> BoxFuture<U256> {
        todo!()
    }

    fn block_transaction_count_by_hash(
        &self, _: H256,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_transaction_count_by_number(
        &self, _: BlockNumber,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_uncles_count_by_hash(&self, _: H256) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn block_uncles_count_by_number(
        &self, _: BlockNumber,
    ) -> BoxFuture<Option<U256>> {
        todo!()
    }

    fn code_at(
        &self, address: H160, epoch_num: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<Bytes> {
        let epoch_num = epoch_num.unwrap_or(BlockNumber::LatestState).into();

        info!(
            "RPC Request: eth_getCode address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

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

    fn send_raw_transaction(&self, raw: Bytes) -> jsonrpc_core::Result<H256> {
        let tx: TransactionWithSignature =
            invalid_params_check("raw", Rlp::new(&raw.into_vec()).as_val())?;

        if tx.space() != Space::Ethereum {
            bail!(invalid_params("tx", "Incorrect transaction space"));
        }

        if tx.recover_public().is_err() {
            bail!(invalid_params(
                "tx",
                "Can not recover pubkey for Ethereum like tx"
            ));
        }

        let r = self.send_transaction_with_signature(tx)?;
        Ok(r)
    }

    fn submit_transaction(&self, raw: Bytes) -> jsonrpc_core::Result<H256> {
        self.send_raw_transaction(raw)
    }

    fn call(
        &self, request: CallRequest, epoch: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<Bytes> {
        // TODO: Check the EVM error message. To make the assert_error_eq test
        // case in solidity project compatible.
        match self.exec_transaction(request, epoch)? {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(expected, got)) => {
                bail!(call_execution_error(
                    "Transaction can not be executed".into(),
                    format! {"nonce is too old expected {:?} got {:?}", expected, got}.into_bytes()
                ))
            }
            ExecutionOutcome::NotExecutedDrop(TxDropError::InvalidRecipientAddress(recipient)) => {
                bail!(call_execution_error(
                    "Transaction can not be executed".into(),
                    format! {"invalid recipient address {:?}", recipient}.into_bytes()
                ))
            }
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(call_execution_error(
                    "Transaction can not be executed".into(),
                    format! {"{:?}", e}.into_bytes()
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(vm::Error::Reverted),
                executed,
            ) => bail!(call_execution_error(
                "Transaction reverted".into(),
                executed.output
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                bail!(call_execution_error(
                    "Transaction execution failed".into(),
                    format! {"{:?}", e}.into_bytes()
                ))
            }
            ExecutionOutcome::Finished(executed) => Ok(executed.output.into()),
        }
    }

    fn estimate_gas(
        &self, request: CallRequest, epoch: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<U256> {
        // TODO: Check the EVM error message. To make the assert_error_eq test
        // case in solidity project compatible.
        let executed = match self.exec_transaction(request, epoch)? {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(expected, got)) => {
                bail!(call_execution_error(
                    "Can not estimate: transaction can not be executed".into(),
                    format! {"nonce is too old expected {:?} got {:?}", expected, got}.into_bytes()
                ))
            }
            ExecutionOutcome::NotExecutedDrop(TxDropError::InvalidRecipientAddress(recipient)) => {
                bail!(call_execution_error(
                    "Can not estimate: transaction can not be executed".into(),
                    format! {"invalid recipient address {:?}", recipient}.into_bytes()
                ))
            }
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(call_execution_error(
                    "Can not estimate: transaction can not be executed".into(),
                    format! {"{:?}", e}.into_bytes()
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(vm::Error::Reverted),
                executed,
            ) => {
                // When a revert exception happens, there is usually an error in the sub-calls.
                // So we return the trace information for debugging contract.
                let errors = ErrorUnwind::from_traces(executed.trace).errors.iter()
                    .map(|(addr,error)| {
                        format!("{}: {}", addr, error)
                    })
                    .collect::<Vec<String>>();

                // Decode revert error
                let revert_error = revert_reason_decode(&executed.output);
                let revert_error = if !revert_error.is_empty() {
                    format!(": {}.",revert_error)
                }else{
                    format!(".")
                };

                // Try to fetch the innermost error.
                let innermost_error = if errors.len()>0{
                    format!(" Innermost error is at {}.", errors[0])
                }else{
                    String::default()
                };

                bail!(call_execution_error(
                    format!("Estimation isn't accurate: transaction is reverted{}{}",
                        revert_error, innermost_error),
                    errors.join("\n").into_bytes(),
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                bail!(call_execution_error(
                    format! {"Can not estimate: transaction execution failed, \
                    all gas will be charged (execution error: {:?})", e}
                    .into(),
                    format! {"{:?}", e}.into_bytes()
                ))
            }
            ExecutionOutcome::Finished(executed) => executed,
        };

        // In case of unlimited full gas charge at some VM call, or if there are
        // infinite loops, the total estimated gas used is very close to
        // MAX_GAS_CALL_REQUEST, 0.8 is chosen to check if it's close.
        const TOO_MUCH_GAS_USED: u64 =
            (0.8 * (MAX_GAS_CALL_REQUEST as f32)) as u64;
        if executed.gas_used >= U256::from(TOO_MUCH_GAS_USED) {
            bail!(call_execution_error(
                format!(
                    "Gas too high. Most likely there are problems within the contract code. \
                    gas {}",
                    executed.gas_used
                ),
                format!(
                    "gas {}", executed.gas_used
                )
                .into_bytes(),
            ));
        }
        Ok(executed.gas_used * 4 / 3)
    }

    fn transaction_by_hash(
        &self, hash: H256,
    ) -> jsonrpc_core::Result<Option<Transaction>> {
        info!("RPC Request: eth_getTransactionByHash({:?})", hash);

        if let Some((tx, _)) =
            self.consensus.get_transaction_info_by_hash(&hash)
        {
            return if tx.space() == Space::Ethereum {
                Ok(Some(Transaction::from_signed(&tx)))
            } else {
                Ok(None)
            };
        }

        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            return if tx.space() == Space::Ethereum {
                Ok(Some(Transaction::from_signed(&tx)))
            } else {
                Ok(None)
            };
        }

        Ok(None)
    }

    fn transaction_by_block_hash_and_index(
        &self, _: H256, _: Index,
    ) -> BoxFuture<Option<Transaction>> {
        todo!()
    }

    fn transaction_by_block_number_and_index(
        &self, _: BlockNumber, _: Index,
    ) -> BoxFuture<Option<Transaction>> {
        todo!()
    }

    fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> jsonrpc_core::Result<Option<Receipt>> {
        let tx_index =
            match self.consensus.get_data_manager().transaction_index_by_hash(
                &tx_hash, false, /* update_cache */
            ) {
                None => return Ok(None),
                Some(tx_index) => tx_index,
            };

        let exec_info =
            match self.get_block_execution_info(&tx_index.block_hash)? {
                None => return Ok(None),
                Some(res) => res,
            };

        let receipt = self.construct_rpc_receipt(tx_index, &exec_info)?;
        Ok(Some(receipt))
    }

    fn uncle_by_block_hash_and_index(
        &self, _: H256, _: Index,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn uncle_by_block_number_and_index(
        &self, _: BlockNumber, _: Index,
    ) -> BoxFuture<Option<RichBlock>> {
        todo!()
    }

    fn logs(&self, _: Filter) -> BoxFuture<Vec<Log>> { todo!() }

    fn submit_hashrate(&self, _: U256, _: H256) -> jsonrpc_core::Result<bool> {
        todo!()
    }
}

impl EthFilter for EthHandler {
    fn new_filter(&self, _: Filter) -> jsonrpc_core::Result<U256> { todo!() }

    fn new_block_filter(&self) -> jsonrpc_core::Result<U256> { todo!() }

    fn new_pending_transaction_filter(&self) -> jsonrpc_core::Result<U256> {
        todo!()
    }

    fn filter_changes(&self, _: Index) -> BoxFuture<FilterChanges> { todo!() }

    fn filter_logs(&self, _: Index) -> BoxFuture<Vec<Log>> { todo!() }

    fn uninstall_filter(&self, _: Index) -> jsonrpc_core::Result<bool> {
        todo!()
    }
}
