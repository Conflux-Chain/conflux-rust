// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{sync::Arc, thread, time::Duration};

use async_trait::async_trait;
use bigdecimal::BigDecimal;
use blockgen::BlockGeneratorTestApi;
use cfx_addr::Network;
use cfx_execute_helper::estimation::{
    decode_error, EstimateExt, EstimateRequest,
};
use cfx_executor::{
    executive::{ExecutionError, ExecutionOutcome, TxDropError},
    internal_contract::storage_point_prop,
    state::State,
};
use cfx_parameters::{
    consensus_internal::REWARD_EPOCH_COUNT,
    genesis::{
        genesis_contract_address_four_year, genesis_contract_address_two_year,
    },
    rpc::GAS_PRICE_DEFAULT_VALUE,
    staking::{BLOCKS_PER_YEAR, DRIPS_PER_STORAGE_COLLATERAL_UNIT},
};
use cfx_rpc_cfx_api::{CfxDebugRpcServer, CfxRpcServer};
use cfx_rpc_cfx_types::{
    address::{check_rpc_address_network, check_two_rpc_address_network_match},
    pos::PoSEpochReward,
    receipt::Receipt as RpcReceipt,
    transaction::PackedOrExecuted,
    Account as RpcAccount, AccountPendingInfo, AccountPendingTransactions,
    Block as RpcBlock, BlockHashOrEpochNumber, Bytes, CfxFeeHistory,
    CfxRpcLogFilter, CheckBalanceAgainstTransactionResponse, EpochNumber,
    EstimateGasAndCollateralResponse, Log as RpcLog, PoSEconomics,
    RewardInfo as RpcRewardInfo, RpcAddress, RpcImplConfiguration, SponsorInfo,
    Status as RpcStatus, StorageCollateralInfo, TokenSupplyInfo,
    Transaction as RpcTransaction, TransactionRequest, VoteParamsInfo,
};
use cfx_rpc_eth_types::FeeHistory;
use cfx_rpc_primitives::U64 as HexU64;
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    call_execution_error, internal_error, internal_error_with_data,
    invalid_params, invalid_params_check, invalid_params_msg,
    invalid_params_rpc_err, pivot_assumption_failed,
    request_rejected_in_catch_up_mode,
};
use cfx_statedb::{
    global_params::{
        AccumulateInterestRate, BaseFeeProp, DistributablePoSInterest,
        InterestRate, LastDistributeBlock, PowBaseReward, TotalBurnt1559,
        TotalPosStaking,
    },
    StateDbExt,
};
use cfx_storage::state::StateDbGetOriginalMethods;
use cfx_types::{
    Address, AddressSpaceUtil, BigEndianHash, Space, H160, H256, H520, U128,
    U256, U64,
};
use cfx_util_macros::bail;
use cfx_vm_types::Error as VmError;
use cfxcore::{
    block_data_manager::BlockDataManager,
    consensus::{
        pos_handler::PosVerifier, MaybeExecutedTxExtraInfo, TransactionInfo,
    },
    consensus_parameters::DEFERRED_STATE_EPOCH_COUNT,
    errors::{
        account_result_to_rpc_result, Error as CoreError, Result as CoreResult,
    },
    ConsensusGraph, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use diem_crypto::hash::HashValue;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use log::{debug, info, trace, warn};
use num_bigint::{BigInt, ToBigInt};
use primitives::{
    filter::LogFilter, Account, Block, BlockHeader, BlockReceipts, DepositInfo,
    EpochNumber as PrimitiveEpochNumber, StorageKey, StorageRoot, StorageValue,
    TransactionIndex, TransactionStatus, TransactionWithSignature,
    VoteStakeInfo,
};
use rustc_hex::ToHex;
use storage_interface::DBReaderForPoW;

use crate::{
    eth_data_hash, helpers::build_block,
    pos_handler::convert_to_pos_epoch_reward,
};

fn into_rpc_err<E>(e: E) -> ErrorObjectOwned
where CoreError: From<E> {
    ErrorObjectOwned::from(CoreError::from(e))
}

/// Helper struct to track block execution info for receipt construction
#[derive(Debug)]
struct BlockExecInfo {
    block_receipts: Arc<BlockReceipts>,
    block: Arc<Block>,
    epoch_number: u64,
    maybe_state_root: Option<H256>,
    pivot_header: Arc<BlockHeader>,
}

pub struct CfxHandler {
    pub config: RpcImplConfiguration,
    pub consensus: SharedConsensusGraph,
    pub sync: SharedSynchronizationService,
    pub tx_pool: SharedTransactionPool,
    pub accounts: Arc<AccountProvider>,
    pub data_man: Arc<BlockDataManager>,
    pub network_type: Network,
    pub pos_handler: Arc<PosVerifier>,
    block_gen: BlockGeneratorTestApi,
}

impl CfxHandler {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        accounts: Arc<AccountProvider>, pos_handler: Arc<PosVerifier>,
        block_gen: BlockGeneratorTestApi,
    ) -> Self {
        let data_man = consensus.data_manager().clone();
        let network_type = *sync.network.get_network_type();
        CfxHandler {
            config,
            consensus,
            sync,
            tx_pool,
            accounts,
            data_man,
            network_type,
            pos_handler,
            block_gen,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph { &self.consensus }

    fn check_address_network(&self, network: Network) -> RpcResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(Some(network), &self.network_type),
        )
    }

    fn get_epoch_number_with_pivot_check(
        &self, block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> CoreResult<EpochNumber> {
        match block_hash_or_epoch_number {
            Some(BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            }) => {
                let epoch_number = self
                    .consensus_graph()
                    .get_block_epoch_number_with_pivot_check(
                        &hash,
                        require_pivot.unwrap_or(true),
                    )?;
                Ok(EpochNumber::Num(U64::from(epoch_number)))
            }
            Some(BlockHashOrEpochNumber::EpochNumber(epoch_number)) => {
                Ok(match epoch_number {
                    PrimitiveEpochNumber::Number(n) => {
                        EpochNumber::Num(cfx_types::U64::from(n))
                    }
                    PrimitiveEpochNumber::Earliest => EpochNumber::Earliest,
                    PrimitiveEpochNumber::LatestCheckpoint => {
                        EpochNumber::LatestCheckpoint
                    }
                    PrimitiveEpochNumber::LatestFinalized => {
                        EpochNumber::LatestFinalized
                    }
                    PrimitiveEpochNumber::LatestConfirmed => {
                        EpochNumber::LatestConfirmed
                    }
                    PrimitiveEpochNumber::LatestState => {
                        EpochNumber::LatestState
                    }
                    PrimitiveEpochNumber::LatestMined => {
                        EpochNumber::LatestMined
                    }
                })
            }
            None => Ok(EpochNumber::LatestState),
        }
    }

    fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> CoreResult<Option<BlockExecInfo>> {
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
            .data_manager()
            .block_header_by_hash(&pivot_hash)
            .ok_or("Inconsistent state")?
            .height();

        if epoch_number > consensus_graph.best_executed_state_epoch_number() {
            return Ok(None);
        }

        let block = self
            .consensus
            .data_manager()
            .block_by_hash(&block_hash, false)
            .ok_or("Inconsistent state")?;

        if block_receipts.receipts.len() != block.transactions.len() {
            bail!("Inconsistent state");
        }

        let pivot_header = match self
            .consensus
            .data_manager()
            .block_header_by_hash(&pivot_hash)
        {
            Some(x) => x,
            None => {
                warn!("Cannot find pivot header when get block execution info: pivot hash {:?}", pivot_hash);
                return Ok(None);
            }
        };

        Ok(Some(BlockExecInfo {
            block_receipts,
            block,
            epoch_number,
            maybe_state_root,
            pivot_header,
        }))
    }

    fn construct_rpc_receipt(
        &self, tx_index: TransactionIndex, exec_info: &BlockExecInfo,
        include_eth_receipt: bool, include_accumulated_gas_used: bool,
    ) -> CoreResult<Option<RpcReceipt>> {
        let id = tx_index.real_index;

        if id >= exec_info.block.transactions.len()
            || id >= exec_info.block_receipts.receipts.len()
            || id >= exec_info.block_receipts.tx_execution_error_messages.len()
        {
            bail!("Inconsistent state");
        }

        let tx = &exec_info.block.transactions[id];

        if !include_eth_receipt
            && (tx.space() == Space::Ethereum || tx_index.is_phantom)
        {
            return Ok(None);
        }

        let prior_gas_used = match id {
            0 => U256::zero(),
            id => {
                exec_info.block_receipts.receipts[id - 1].accumulated_gas_used
            }
        };

        let tx_exec_error_msg =
            match &exec_info.block_receipts.tx_execution_error_messages[id] {
                msg if msg.is_empty() => None,
                msg => Some(msg.clone()),
            };

        let receipt = RpcReceipt::new(
            (**tx).clone(),
            exec_info.block_receipts.receipts[id].clone(),
            tx_index,
            prior_gas_used,
            Some(exec_info.epoch_number),
            exec_info.block_receipts.block_number,
            exec_info.pivot_header.base_price(),
            exec_info.maybe_state_root.clone(),
            tx_exec_error_msg,
            self.network_type,
            include_eth_receipt,
            include_accumulated_gas_used,
        )?;

        Ok(Some(receipt))
    }

    fn prepare_receipt(&self, tx_hash: H256) -> CoreResult<Option<RpcReceipt>> {
        let tx_index = match self
            .consensus
            .data_manager()
            .transaction_index_by_hash(&tx_hash, false)
        {
            None => return Ok(None),
            Some(tx_index) => tx_index,
        };

        if tx_index.is_phantom {
            return Ok(None);
        }

        let exec_info =
            match self.get_block_execution_info(&tx_index.block_hash)? {
                None => return Ok(None),
                Some(res) => res,
            };

        let receipt =
            self.construct_rpc_receipt(tx_index, &exec_info, false, true)?;
        if let Some(r) = &receipt {
            if r.outcome_status
                == TransactionStatus::Skipped.in_space(Space::Native).into()
            {
                return Ok(None);
            }
        }
        Ok(receipt)
    }

    fn prepare_block_receipts(
        &self, block_hash: H256, pivot_assumption: H256,
        include_eth_receipt: bool,
    ) -> CoreResult<Option<Vec<RpcReceipt>>> {
        let exec_info = match self.get_block_execution_info(&block_hash)? {
            None => return Ok(None),
            Some(res) => res,
        };

        if pivot_assumption != exec_info.pivot_header.hash() {
            bail!(pivot_assumption_failed(
                pivot_assumption,
                exec_info.pivot_header.hash()
            ));
        }

        let mut rpc_receipts = vec![];

        let iter = exec_info
            .block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| {
                if include_eth_receipt {
                    true
                } else {
                    tx.space() == Space::Native
                }
            })
            .enumerate();

        for (new_index, (original_index, _)) in iter {
            if let Some(receipt) = self.construct_rpc_receipt(
                TransactionIndex {
                    block_hash,
                    real_index: original_index,
                    is_phantom: false,
                    rpc_index: Some(new_index),
                },
                &exec_info,
                include_eth_receipt,
                true,
            )? {
                rpc_receipts.push(receipt);
            }
        }

        Ok(Some(rpc_receipts))
    }

    fn exec_transaction(
        &self, request: TransactionRequest, epoch: Option<EpochNumber>,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        let rpc_request_network = invalid_params_check(
            "request",
            check_two_rpc_address_network_match(
                request.from.as_ref(),
                request.to.as_ref(),
            ),
        )?;

        invalid_params_check(
            "request",
            check_rpc_address_network(rpc_request_network, &self.network_type),
        )?;

        let consensus_graph = self.consensus_graph();
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);

        let estimate_request = EstimateRequest {
            has_sender: request.from.is_some(),
            has_gas_limit: request.gas.is_some(),
            has_gas_price: request.has_gas_price(),
            has_nonce: request.nonce.is_some(),
            has_storage_limit: request.storage_limit.is_some(),
        };

        let epoch_height = consensus_graph
            .get_height_from_epoch_number(epoch.clone().into())?;
        let chain_id = consensus_graph.best_chain_id();
        let signed_tx = request.sign_call(
            epoch_height,
            chain_id.in_native_space(),
            self.config.max_estimation_gas_limit,
        )?;
        trace!("call tx {:?}", signed_tx);

        consensus_graph.call_virtual(
            &signed_tx,
            epoch.into(),
            estimate_request,
            Default::default(),
        )
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> CoreResult<H256> {
        if self.sync.catch_up_mode() {
            warn!("Ignore send_transaction request {}. Cannot send transaction when the node is still in catch-up mode.", tx.hash());
            bail!(request_rejected_in_catch_up_mode(None));
        }
        let (signed_trans, failed_trans) =
            self.tx_pool.insert_new_transactions(vec![tx]);

        match (signed_trans.len(), failed_trans.len()) {
            (0, 0) => {
                debug!("insert_new_transactions ignores inserted transactions");
                bail!(invalid_params("tx", Some("tx already exist")))
            }
            (0, 1) => {
                let tx_err = failed_trans.values().next().unwrap();
                bail!(invalid_params("tx", Some(tx_err.to_string())))
            }
            (1, 0) => {
                let tx_hash = signed_trans[0].hash();
                self.sync.append_received_transactions(signed_trans);
                Ok(tx_hash)
            }
            _ => {
                bail!(internal_error_with_data(format!(
                    "unexpected insert result, {} returned items",
                    signed_trans.len() + failed_trans.len()
                )))
            }
        }
    }

    fn prepare_transaction(
        &self, mut tx: TransactionRequest, password: Option<String>,
    ) -> CoreResult<TransactionWithSignature> {
        let consensus_graph = self.consensus_graph();
        tx.check_rpc_address_network("tx", &self.network_type)?;

        if tx.nonce.is_none() {
            let nonce = consensus_graph.next_nonce(
                Address::from(tx.from.clone().ok_or("from should have")?)
                    .with_native_space(),
                BlockHashOrEpochNumber::EpochNumber(
                    PrimitiveEpochNumber::LatestState,
                ),
                "internal EpochNumber::LatestState",
            )?;
            tx.nonce.replace(nonce.into());
            debug!("after loading nonce in latest state, tx = {:?}", tx);
        }

        let epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();

        if tx.gas.is_none() || tx.storage_limit.is_none() {
            let estimate =
                self.estimate_gas_and_collateral_impl(tx.clone(), None)?;

            if tx.gas.is_none() {
                tx.gas.replace(estimate.gas_used);
            }

            if tx.storage_limit.is_none() {
                tx.storage_limit.replace(estimate.storage_collateralized);
            }
        }

        if tx.transaction_type.is_none() && tx.gas_price.is_none() {
            let gas_price = consensus_graph.gas_price(Space::Native);
            if gas_price.is_some() {
                tx.gas_price.replace(gas_price.unwrap());
            }
        }

        tx.sign_with(
            epoch_height,
            chain_id.in_native_space(),
            password,
            self.accounts.clone(),
        )
        .map_err(Into::into)
    }

    fn estimate_gas_and_collateral_impl(
        &self, request: TransactionRequest, epoch: Option<EpochNumber>,
    ) -> CoreResult<EstimateGasAndCollateralResponse> {
        let (execution_outcome, estimation) =
            self.exec_transaction(request, epoch)?;
        match execution_outcome {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                expected,
                got,
            )) => bail!(call_execution_error(
                "Can not estimate: transaction can not be executed".into(),
                format! {"nonce is too old expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::InvalidRecipientAddress(recipient),
            ) => bail!(call_execution_error(
                "Can not estimate: transaction can not be executed".into(),
                format! {"invalid recipient address {:?}", recipient}
            )),
            ExecutionOutcome::NotExecutedDrop(TxDropError::SenderWithCode(
                address,
            )) => bail!(call_execution_error(
                "Can not estimate: transaction sender has code".into(),
                format! {"transaction sender has code {:?}", address}
            )),
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(call_execution_error(
                    "Can not estimate: transaction can not be executed".into(),
                    format! {"{:?}", e}
                ))
            }
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit { expected, got },
            ) => bail!(call_execution_error(
                "Can not estimate: transaction can not be executed".into(),
                format! {"not enough gas limit with respected to tx size: expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(VmError::Reverted),
                executed,
            ) => {
                let (revert_error, innermost_error, errors) =
                    decode_error(&executed, |addr| {
                        RpcAddress::try_from_h160(
                            addr.clone(),
                            self.network_type,
                        )
                        .unwrap()
                        .base32_address
                    });
                bail!(call_execution_error(
                    format!("Estimation isn't accurate: transaction is reverted{}{}",
                        revert_error, innermost_error),
                    errors.join("\n"),
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                bail!(call_execution_error(
                    format! {"Can not estimate: transaction execution failed, \
                    all gas will be charged (execution error: {:?})", e}
                    .into(),
                    format! {"{:?}", e}
                ))
            }
            ExecutionOutcome::Finished(_) => {}
        };
        let storage_collateralized =
            U64::from(estimation.estimated_storage_limit);
        let estimated_gas_used = estimation.estimated_gas_limit;
        Ok(EstimateGasAndCollateralResponse {
            gas_limit: estimated_gas_used,
            gas_used: estimated_gas_used,
            storage_collateralized,
        })
    }

    fn check_response_size<T: serde::Serialize>(
        &self, response: &T,
    ) -> CoreResult<()> {
        let max_size = self.config.max_payload_bytes.saturating_sub(50);
        let payload_size = serde_json::to_vec(&response)
            .map_err(|_| "Unexpected serialization error")?
            .len();

        if payload_size > max_size {
            bail!(invalid_params(
                "epoch",
                Some(format!(
                    "Oversized payload: size = {}, max = {}",
                    payload_size, max_size
                ))
            ));
        }
        Ok(())
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> CoreResult<H256> {
        info!("RPC Request: generate_one_block()");
        Ok(self
            .block_gen
            .generate_block(num_txs, block_size_limit, vec![]))
    }
}

#[async_trait]
impl CfxRpcServer for CfxHandler {
    async fn gas_price(&self) -> RpcResult<U256> {
        let consensus_graph = self.consensus_graph();
        info!("RPC Request: cfx_gasPrice()");
        let consensus_gas_price = consensus_graph
            .gas_price(Space::Native)
            .unwrap_or(GAS_PRICE_DEFAULT_VALUE.into())
            .into();
        Ok(std::cmp::max(
            consensus_gas_price,
            self.tx_pool.config.min_native_tx_price.into(),
        ))
    }

    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        info!("RPC Request: max_priority_fee_per_gas");
        let fee_history = self
            .fee_history(
                HexU64::from(300),
                EpochNumber::LatestState,
                Some(vec![50f64]),
            )
            .await?;
        let total_reward: U256 = fee_history
            .reward()
            .iter()
            .map(|x| x.first().unwrap())
            .fold(U256::zero(), |x, y| x + *y);
        Ok(total_reward / 300)
    }

    async fn epoch_number(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let consensus_graph = self.consensus_graph();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber({:?})", epoch_num);
        consensus_graph
            .get_height_from_epoch_number(epoch_num.into())
            .map(|h| h.into())
            .map_err(|e| into_rpc_err(e.to_string()))
    }

    async fn balance(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(addr.network)?;
        let epoch_num = self
            .get_epoch_number_with_pivot_check(block_hash_or_epoch_number)?
            .into();
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?;
        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    async fn admin(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcAddress>> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let network = addr.network;
        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        match state_db
            .get_account(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?
        {
            None => Ok(None),
            Some(acc) => Ok(Some(
                RpcAddress::try_from_h160(acc.admin, network)
                    .map_err(into_rpc_err)?,
            )),
        }
    }

    async fn sponsor_info(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<SponsorInfo> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let network = addr.network;
        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        match state_db
            .get_account(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?
        {
            None => SponsorInfo::default(network).map_err(into_rpc_err),
            Some(acc) => SponsorInfo::try_from(acc.sponsor_info, network)
                .map_err(into_rpc_err),
        }
    }

    async fn staking_balance(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?;
        Ok(acc.map_or(U256::zero(), |acc| acc.staking_balance).into())
    }

    async fn deposit_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Vec<DepositInfo>> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getDepositList address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        match state_db
            .get_deposit_list(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?
        {
            None => Ok(vec![]),
            Some(deposit_list) => Ok(deposit_list.0),
        }
    }

    async fn vote_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Vec<VoteStakeInfo>> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getVoteList address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        match state_db
            .get_vote_list(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?
        {
            None => Ok(vec![]),
            Some(vote_list) => Ok(vote_list.0),
        }
    }

    async fn collateral_for_storage(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(addr.network)?;
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc = state_db
            .get_account(&addr.hex_address.with_native_space())
            .map_err(into_rpc_err)?;
        Ok(acc
            .map_or(U256::zero(), |acc| acc.collateral_for_storage)
            .into())
    }

    async fn code(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Bytes> {
        self.check_address_network(addr.network)?;
        let epoch_num = self
            .get_epoch_number_with_pivot_check(block_hash_or_epoch_number)
            .map_err(into_rpc_err)?
            .into();
        info!(
            "RPC Request: cfx_getCode address={:?} epoch_num={:?}",
            addr, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let address = addr.hex_address.with_native_space();
        let code = match state_db.get_account(&address).map_err(into_rpc_err)? {
            Some(acc) => match state_db
                .get_code(&address, &acc.code_hash)
                .map_err(into_rpc_err)?
            {
                Some(code) => (*code.code).clone(),
                _ => vec![],
            },
            None => vec![],
        };
        Ok(Bytes::new(code))
    }

    async fn storage_at(
        &self, addr: RpcAddress, pos: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Option<H256>> {
        self.check_address_network(addr.network)?;
        let epoch_num = self
            .get_epoch_number_with_pivot_check(block_hash_or_epoch_number)
            .map_err(into_rpc_err)?
            .into();
        info!(
            "RPC Request: cfx_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            addr, pos, epoch_num
        );
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;
        let position: H256 = H256::from_uint(&pos);
        let key =
            StorageKey::new_storage_key(&addr.hex_address, position.as_ref())
                .with_native_space();
        Ok(
            match state_db.get::<StorageValue>(key).map_err(into_rpc_err)? {
                Some(entry) => {
                    let h: H256 = H256::from_uint(&entry.value);
                    Some(h.into())
                }
                None => None,
            },
        )
    }

    async fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<StorageRoot>> {
        self.check_address_network(address.network)?;
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getStorageRoot address={:?} epoch={:?}",
            address, epoch_num
        );
        let root = self
            .consensus
            .get_storage_state_by_epoch_number(epoch_num, "epoch_num")?
            .get_original_storage_root(&address.hex_address.with_native_space())
            .map_err(into_rpc_err)?;
        Ok(Some(root))
    }

    async fn block_by_hash(
        &self, block_hash: H256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let consensus_graph = self.consensus_graph();
        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            block_hash, include_txs
        );
        let inner = &*consensus_graph.inner.read();
        let maybe_block = self.data_man.block_by_hash(&block_hash, false);
        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(
                build_block(
                    &*b,
                    self.network_type,
                    consensus_graph,
                    inner,
                    &self.data_man,
                    include_txs,
                    Some(Space::Native),
                )
                .map_err(into_rpc_err)?,
            )),
        }
    }

    async fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> RpcResult<RpcBlock> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let epoch_number = epoch_number.as_usize() as u64;
        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        let genesis = self.consensus.data_manager().true_genesis.hash();

        if block_hash == genesis && (pivot_hash != genesis || epoch_number != 0)
        {
            return Err(invalid_params_msg("pivot chain assumption failed"));
        }

        if block_hash != genesis
            && (consensus_graph.get_block_epoch_number(&block_hash)
                != epoch_number.into())
        {
            return Err(invalid_params_msg("pivot chain assumption failed"));
        }

        inner
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        let block = self
            .data_man
            .block_by_hash(&block_hash, false)
            .ok_or(invalid_params_msg("Block not found"))?;

        debug!("Build RpcBlock {}", block.hash());
        build_block(
            &*block,
            self.network_type,
            consensus_graph,
            inner,
            &self.data_man,
            true,
            Some(Space::Native),
        )
        .map_err(into_rpc_err)
    }

    async fn block_by_epoch_number(
        &self, epoch_number: EpochNumber, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        info!("RPC Request: cfx_getBlockByEpochNumber epoch_number={:?} include_txs={:?}", epoch_number, include_txs);
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();

        let epoch_height = consensus_graph
            .get_height_from_epoch_number(epoch_number.into())
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        let pivot_hash = inner
            .get_pivot_hash_from_epoch_number(epoch_height)
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        let maybe_block = self.data_man.block_by_hash(&pivot_hash, false);
        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(
                build_block(
                    &*b,
                    self.network_type,
                    consensus_graph,
                    inner,
                    &self.data_man,
                    include_txs,
                    Some(Space::Native),
                )
                .map_err(into_rpc_err)?,
            )),
        }
    }

    async fn block_by_block_number(
        &self, block_number: U64, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let block_number = block_number.as_u64();
        let consensus_graph = self.consensus_graph();
        info!(
            "RPC Request: cfx_getBlockByBlockNumber block_number={:?} include_txs={:?}",
            block_number, include_txs
        );
        let inner = &*consensus_graph.inner.read();
        let block_hash =
            match self.data_man.hash_by_block_number(block_number, true) {
                None => return Ok(None),
                Some(h) => h,
            };
        let maybe_block = self.data_man.block_by_hash(&block_hash, false);
        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(
                build_block(
                    &*b,
                    self.network_type,
                    consensus_graph,
                    inner,
                    &self.data_man,
                    include_txs,
                    Some(Space::Native),
                )
                .map_err(into_rpc_err)?,
            )),
        }
    }

    async fn best_block_hash(&self) -> RpcResult<H256> {
        info!("RPC Request: cfx_getBestBlockHash()");
        Ok(self.consensus.best_block_hash().into())
    }

    async fn next_nonce(
        &self, addr: RpcAddress, num: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(addr.network)?;
        let consensus_graph = self.consensus_graph();
        let num = num.unwrap_or(BlockHashOrEpochNumber::EpochNumber(
            PrimitiveEpochNumber::LatestState,
        ));
        info!(
            "RPC Request: cfx_getNextNonce address={:?} epoch_num={:?}",
            addr, num
        );
        consensus_graph
            .next_nonce(addr.hex_address.with_native_space(), num.into(), "num")
            .map_err(into_rpc_err)
    }

    async fn send_raw_transaction(&self, raw_tx: Bytes) -> RpcResult<H256> {
        info!(
            "RPC Request: cfx_sendRawTransaction len={:?}",
            raw_tx.0.len()
        );
        debug!("RawTransaction bytes={:?}", raw_tx);

        let tx: TransactionWithSignature = invalid_params_check(
            "raw",
            TransactionWithSignature::from_raw(&raw_tx.into_vec()),
        )?;

        if tx.recover_public().is_err() {
            return Err(invalid_params_rpc_err(
                "tx",
                Some("Can not recover pubkey for Ethereum like tx"),
            ));
        }

        let r = self
            .send_transaction_with_signature(tx)
            .map_err(into_rpc_err);

        if r.is_ok() && self.config.dev_pack_tx_immediately {
            // Try to pack and execute this new tx.
            for _ in 0..DEFERRED_STATE_EPOCH_COUNT {
                let generated = self.generate_one_block(
                    1, /* num_txs */
                    self.sync
                        .get_synchronization_graph()
                        .verification_config
                        .max_block_size_in_bytes,
                )?;
                loop {
                    // Wait for the new block to be fully processed, so all
                    // generated blocks form a chain for
                    // `tx` to be executed.
                    if self.consensus.best_block_hash() == generated {
                        break;
                    } else {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }

        r
    }

    async fn call(
        &self, tx: TransactionRequest,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch = Some(
            self.get_epoch_number_with_pivot_check(block_hash_or_epoch_number)
                .map_err(into_rpc_err)?,
        );
        let (execution_outcome, _estimation) =
            self.exec_transaction(tx, epoch).map_err(into_rpc_err)?;
        match execution_outcome {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                expected,
                got,
            )) => Err(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"nonce is too old expected {:?} got {:?}", expected, got},
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::InvalidRecipientAddress(recipient),
            ) => Err(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"invalid recipient address {:?}", recipient},
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit { expected, got },
            ) => Err(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"not enough gas limit with respected to tx size: expected {:?} got {:?}", expected, got},
            )),
            ExecutionOutcome::NotExecutedDrop(TxDropError::SenderWithCode(
                address,
            )) => Err(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"tx sender has contract code: {:?}", address},
            )),
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                Err(call_execution_error(
                    "Transaction can not be executed".into(),
                    format! {"{:?}", e},
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(VmError::Reverted),
                executed,
            ) => Err(call_execution_error(
                "Transaction reverted".into(),
                format!("0x{}", executed.output.to_hex::<String>()),
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                Err(call_execution_error(
                    "Transaction execution failed".into(),
                    format! {"{:?}", e},
                ))
            }
            ExecutionOutcome::Finished(executed) => Ok(executed.output.into()),
        }
    }

    async fn get_logs(
        &self, filter: CfxRpcLogFilter,
    ) -> RpcResult<Vec<RpcLog>> {
        if let Some(addresses) = &filter.address {
            for address in addresses.iter() {
                invalid_params_check(
                    "filter.address",
                    check_rpc_address_network(
                        Some(address.network),
                        &self.network_type,
                    ),
                )?;
            }
        }

        let consensus_graph = self.consensus_graph();
        info!("RPC Request: cfx_getLogs({:?})", filter);

        let filter: LogFilter = filter.into_primitive()?;

        let logs = consensus_graph
            .logs(filter)
            .map_err(into_rpc_err)?
            .iter()
            .cloned()
            .map(|l| RpcLog::try_from_localized(l, self.network_type))
            .collect::<Result<Vec<_>, _>>()
            .map_err(into_rpc_err)?;

        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if logs.len() > max_limit {
                return Err(invalid_params_rpc_err(
                    "filter",
                    Some(format!(
                        "This query results in too many logs, max limitation is {}, please filter results by a smaller epoch/block range",
                        max_limit
                    )),
                ));
            }
        }

        Ok(logs)
    }

    async fn transaction_by_hash(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcTransaction>> {
        info!("RPC Request: cfx_getTransactionByHash({:?})", tx_hash);

        if let Some((
            tx,
            TransactionInfo {
                tx_index,
                maybe_executed_extra_info,
            },
        )) = self.consensus.get_signed_tx_and_tx_info(&tx_hash)
        {
            if tx.space() == Space::Ethereum || tx_index.is_phantom {
                return Ok(None);
            }

            let packed_or_executed = match maybe_executed_extra_info {
                None => PackedOrExecuted::Packed(tx_index),
                Some(MaybeExecutedTxExtraInfo {
                    receipt,
                    block_number,
                    prior_gas_used,
                    tx_exec_error_msg,
                }) => {
                    let epoch_number = self
                        .consensus
                        .get_block_epoch_number(&tx_index.block_hash);

                    let maybe_state_root = self
                        .consensus
                        .data_manager()
                        .get_executed_state_root(&tx_index.block_hash);

                    let maybe_base_price = self
                        .consensus
                        .data_manager()
                        .block_header_by_hash(&tx_index.block_hash)
                        .and_then(|x| x.base_price());

                    PackedOrExecuted::Executed(
                        RpcReceipt::new(
                            tx.clone(),
                            receipt,
                            tx_index,
                            prior_gas_used,
                            epoch_number,
                            block_number,
                            maybe_base_price,
                            maybe_state_root,
                            tx_exec_error_msg,
                            self.network_type,
                            false,
                            false,
                        )
                        .map_err(into_rpc_err)?,
                    )
                }
            };

            let rpc_tx = RpcTransaction::from_signed(
                &tx,
                Some(packed_or_executed),
                self.network_type,
            )
            .map_err(into_rpc_err)?;

            return Ok(Some(rpc_tx));
        }

        if let Some(tx) = self.tx_pool.get_transaction(&tx_hash) {
            if tx.space() == Space::Ethereum {
                return Ok(None);
            }
            let rpc_tx =
                RpcTransaction::from_signed(&tx, None, self.network_type)
                    .map_err(into_rpc_err)?;
            return Ok(Some(rpc_tx));
        }

        Ok(None)
    }

    async fn estimate_gas_and_collateral(
        &self, request: TransactionRequest, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        info!(
            "RPC Request: cfx_estimateGasAndCollateral request={:?}, epoch={:?}",
            request, epoch_number
        );
        self.estimate_gas_and_collateral_impl(request, epoch_number)
            .map_err(into_rpc_err)
    }

    async fn fee_history(
        &self, block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<CfxFeeHistory> {
        use crate::helpers::MAX_FEE_HISTORY_CACHE_BLOCK_COUNT;

        if newest_block == EpochNumber::LatestMined {
            return Err(invalid_params_rpc_err(
                "newestBlock cannot be 'LatestMined'",
                None::<bool>,
            ));
        }

        info!(
            "RPC Request: cfx_feeHistory: block_count={}, newest_block={:?}, reward_percentiles={:?}",
            block_count, newest_block, reward_percentiles
        );

        let mut block_count = block_count;

        if block_count.as_u64() == 0 {
            return Ok(FeeHistory::new().into());
        }

        if block_count.as_u64() > MAX_FEE_HISTORY_CACHE_BLOCK_COUNT {
            block_count = HexU64::from(MAX_FEE_HISTORY_CACHE_BLOCK_COUNT);
        }

        let inner = self.consensus_graph().inner.read();

        let fetch_block = |height| {
            let pivot_hash = inner
                .get_pivot_hash_from_epoch_number(height)
                .map_err(|e| invalid_params_rpc_err(e, None::<bool>))?;
            let maybe_block = self.data_man.block_by_hash(&pivot_hash, false);
            if let Some(block) = maybe_block {
                Ok(block)
            } else {
                Err(internal_error())
            }
        };

        let start_height: u64 = self
            .consensus_graph()
            .get_height_from_epoch_number(newest_block.into())
            .map_err(|e| invalid_params_rpc_err(e, None::<bool>))?;

        let reward_percentiles = reward_percentiles.unwrap_or_default();
        let mut current_height = start_height;

        let mut fee_history = FeeHistory::new();
        while current_height
            >= start_height.saturating_sub(block_count.as_u64() - 1)
        {
            let block = fetch_block(current_height)?;
            let transactions = block
                .transactions
                .iter()
                .filter(|tx| tx.space() == Space::Native)
                .map(|x| &**x);
            fee_history
                .push_front_block(
                    Space::Native,
                    &reward_percentiles,
                    &block.block_header,
                    transactions,
                )
                .map_err(|_| internal_error())?;

            if current_height == 0 {
                break;
            } else {
                current_height -= 1;
            }
        }

        let block = fetch_block(start_height + 1)?;
        let oldest_block = if current_height == 0 {
            0
        } else {
            current_height + 1
        };
        fee_history.finish(
            oldest_block,
            block.block_header.base_price().as_ref(),
            Space::Native,
        );

        Ok(fee_history.into())
    }

    async fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> RpcResult<CheckBalanceAgainstTransactionResponse> {
        self.check_address_network(account_addr.network)?;
        self.check_address_network(contract_addr.network)?;

        let epoch: PrimitiveEpochNumber =
            epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_checkBalanceAgainstTransaction account_addr={:?} contract_addr={:?} gas_limit={:?} gas_price={:?} storage_limit={:?} epoch={:?}",
            account_addr, contract_addr, gas_limit, gas_price, storage_limit, epoch
        );

        let account_addr_spaced = account_addr.hex_address.with_native_space();
        let contract_addr_spaced =
            contract_addr.hex_address.with_native_space();

        if storage_limit > U256::from(std::u64::MAX) {
            return Err(invalid_params_rpc_err(
                format!(
                    "storage_limit has to be within the range of u64 but {} supplied!",
                    storage_limit
                ),
                None::<bool>,
            ));
        }

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch, "epoch")
            .map_err(into_rpc_err)?;

        let user_account = state_db
            .get_account(&account_addr_spaced)
            .map_err(into_rpc_err)?;
        let contract_account = state_db
            .get_account(&contract_addr_spaced)
            .map_err(into_rpc_err)?;
        let state = State::new(state_db).map_err(into_rpc_err)?;
        let is_sponsored = state
            .check_contract_whitelist(
                &contract_addr_spaced.address,
                &account_addr_spaced.address,
            )
            .map_err(into_rpc_err)?;

        Ok(check_balance_against_transaction(
            user_account,
            contract_account,
            is_sponsored,
            gas_limit,
            gas_price,
            storage_limit,
        ))
    }

    async fn blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<Vec<H256>> {
        info!(
            "RPC Request: cfx_getBlocksByEpoch epoch_number={:?}",
            epoch_number
        );
        self.consensus
            .get_block_hashes_by_epoch(epoch_number.into())
            .map_err(|e| invalid_params_rpc_err(e, None::<bool>))
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    async fn skipped_blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<Vec<H256>> {
        info!(
            "RPC Request: cfx_getSkippedBlocksByEpoch epoch_number={:?}",
            epoch_number
        );
        self.consensus
            .get_skipped_block_hashes_by_epoch(epoch_number.into())
            .map_err(|e| invalid_params_rpc_err(e, None::<bool>))
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    async fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        info!("RPC Request: cfx_getTransactionReceipt({:?})", tx_hash);
        self.prepare_receipt(tx_hash).map_err(into_rpc_err)
    }

    async fn account(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        self.check_address_network(address.network)?;
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;
        info!(
            "RPC Request: cfx_getAccount address={:?} epoch_num={:?}",
            address, epoch_num
        );
        let addr = &address.hex_address;
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")
            .map_err(into_rpc_err)?;
        let account = match state_db
            .get_account(&addr.with_native_space())
            .map_err(into_rpc_err)?
        {
            Some(t) => t,
            None => account_result_to_rpc_result(
                "address",
                Ok(Account::new_empty_with_balance(
                    &addr.with_native_space(),
                    &U256::zero(),
                    &U256::zero(),
                )),
            )
            .map_err(into_rpc_err)?,
        };
        RpcAccount::try_from(account, network)
            .map_err(|e| invalid_params_rpc_err(e, None::<bool>))
    }

    async fn interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")
            .map_err(into_rpc_err)?;
        Ok(state_db
            .get_global_param::<InterestRate>()
            .map_err(into_rpc_err)?
            .into())
    }

    async fn accumulate_interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")
            .map_err(into_rpc_err)?;
        Ok(state_db
            .get_global_param::<AccumulateInterestRate>()
            .map_err(into_rpc_err)?
            .into())
    }

    async fn pos_economics(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<PoSEconomics> {
        let epoch_num = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")
            .map_err(into_rpc_err)?;
        Ok(PoSEconomics {
            total_pos_staking_tokens: state_db
                .get_global_param::<TotalPosStaking>()
                .map_err(into_rpc_err)?,
            distributable_pos_interest: state_db
                .get_global_param::<DistributablePoSInterest>()
                .map_err(into_rpc_err)?,
            last_distribute_block: U64::from(
                state_db
                    .get_global_param::<LastDistributeBlock>()
                    .map_err(into_rpc_err)?
                    .as_u64(),
            ),
        })
    }

    async fn confirmation_risk_by_hash(
        &self, block_hash: H256,
    ) -> RpcResult<Option<U256>> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let result = consensus_graph
            .confirmation_meter
            .confirmation_risk_by_hash(inner, block_hash.into());
        if result.is_none() {
            return Ok(None);
        }
        let risk: BigDecimal = result.unwrap().into();
        let scale = BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            16,
        )
        .expect("failed to unwrap U256::max into bigInt");
        let scaled_risk: BigInt = (risk * scale)
            .to_bigint()
            .expect("failed to convert scaled risk to bigInt");
        let (sign, big_endian_bytes) = scaled_risk.to_bytes_be();
        assert_ne!(sign, num_bigint::Sign::Minus);
        let rpc_result = U256::from(big_endian_bytes.as_slice());
        Ok(Some(rpc_result.into()))
    }

    async fn get_status(&self) -> RpcResult<RpcStatus> {
        let consensus_graph = self.consensus_graph();
        let (best_info, block_number) = {
            let _inner = &*consensus_graph.inner.read();
            let best_info = self.consensus.best_info();
            let block_number = self
                .consensus
                .get_block_number(&best_info.best_block_hash)
                .map_err(into_rpc_err)?
                .ok_or_else(|| internal_error())?
                + 1;
            (best_info, block_number)
        };

        let tx_count = self.tx_pool.total_unpacked();

        let latest_checkpoint = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestCheckpoint.into())
            .map_err(into_rpc_err)?
            .into();

        let latest_confirmed = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestConfirmed.into())
            .map_err(into_rpc_err)?
            .into();

        let latest_state = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestState.into())
            .map_err(into_rpc_err)?
            .into();

        let latest_finalized = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestFinalized.into())
            .map_err(into_rpc_err)?
            .into();

        Ok(RpcStatus {
            best_hash: best_info.best_block_hash.into(),
            block_number: block_number.into(),
            chain_id: best_info.chain_id.in_native_space().into(),
            ethereum_space_chain_id: best_info
                .chain_id
                .in_space(Space::Ethereum)
                .into(),
            epoch_number: best_info.best_epoch_number.into(),
            latest_checkpoint,
            latest_confirmed,
            latest_finalized,
            latest_state,
            network_id: self.sync.network.network_id().into(),
            pending_tx_number: tx_count.into(),
        })
    }

    async fn get_block_reward_info(
        &self, num: EpochNumber,
    ) -> RpcResult<Vec<RpcRewardInfo>> {
        info!("RPC Request: cfx_getBlockRewardInfo epoch_number={:?}", num);
        let epoch_height: U64 = self
            .consensus_graph()
            .get_height_from_epoch_number(num.clone().into_primitive())
            .map_err(|e| invalid_params_rpc_err(e, None::<bool>))?
            .into();
        let (epoch_later_number, overflow) =
            epoch_height.overflowing_add(REWARD_EPOCH_COUNT.into());
        if overflow {
            return Err(invalid_params_rpc_err(
                "Epoch number overflows!",
                None::<bool>,
            ));
        }
        let epoch_later = match self.consensus.get_hash_from_epoch_number(
            EpochNumber::Num(epoch_later_number).into_primitive(),
        ) {
            Ok(hash) => hash,
            Err(e) => {
                debug!(
                    "get_block_reward_info: get_hash_from_epoch_number returns error: {}",
                    e
                );
                return Err(invalid_params_rpc_err(
                    "Reward not calculated yet!",
                    None::<bool>,
                ));
            }
        };

        let blocks = self
            .consensus
            .get_block_hashes_by_epoch(num.into())
            .map_err(into_rpc_err)?;

        let mut ret = Vec::new();
        for b in blocks {
            if let Some(reward_result) = self
                .consensus
                .data_manager()
                .block_reward_result_by_hash_with_epoch(
                    &b,
                    &epoch_later,
                    false,
                    true,
                )
            {
                if let Some(block_header) =
                    self.consensus.data_manager().block_header_by_hash(&b)
                {
                    let author = RpcAddress::try_from_h160(
                        *block_header.author(),
                        self.network_type,
                    )
                    .map_err(|e| invalid_params_rpc_err(e, None::<bool>))?;

                    ret.push(RpcRewardInfo {
                        block_hash: b.into(),
                        author,
                        total_reward: reward_result.total_reward.into(),
                        base_reward: reward_result.base_reward.into(),
                        tx_fee: reward_result.tx_fee.into(),
                    })
                }
            }
        }
        Ok(ret)
    }

    async fn get_client_version(&self) -> RpcResult<String> {
        Ok(parity_version::conflux_client_version!())
    }

    async fn get_supply_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<TokenSupplyInfo> {
        let epoch = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state = State::new(
            self.consensus
                .get_state_db_by_epoch_number(epoch, "epoch")
                .map_err(into_rpc_err)?,
        )
        .map_err(into_rpc_err)?;
        let total_issued = state.total_issued_tokens();
        let total_staking = state.total_staking_tokens();
        let total_collateral = state.total_storage_tokens();
        let two_year_unlock_address = genesis_contract_address_two_year();
        let four_year_unlock_address = genesis_contract_address_four_year();
        let two_year_locked = state
            .balance(&two_year_unlock_address)
            .unwrap_or(U256::zero());
        let four_year_locked = state
            .balance(&four_year_unlock_address)
            .unwrap_or(U256::zero());
        let total_circulating =
            total_issued - two_year_locked - four_year_locked;
        let total_espace_tokens = state.total_espace_tokens();
        Ok(TokenSupplyInfo {
            total_circulating,
            total_issued,
            total_staking,
            total_collateral,
            total_espace_tokens,
        })
    }

    async fn get_collateral_info(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<StorageCollateralInfo> {
        let epoch = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state = State::new(
            self.consensus
                .get_state_db_by_epoch_number(epoch, "epoch")
                .map_err(into_rpc_err)?,
        )
        .map_err(into_rpc_err)?;
        let total_storage_tokens = state.total_storage_tokens();
        let converted_storage_points = state.converted_storage_points()
            / *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        let used_storage_points =
            state.used_storage_points() / *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        Ok(StorageCollateralInfo {
            total_storage_tokens,
            converted_storage_points,
            used_storage_points,
        })
    }

    async fn get_fee_burnt(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch, "epoch_num")
            .map_err(into_rpc_err)?;
        Ok(state_db
            .get_global_param::<TotalBurnt1559>()
            .map_err(into_rpc_err)?)
    }

    async fn get_pos_reward_by_epoch(
        &self, epoch: EpochNumber,
    ) -> RpcResult<Option<PoSEpochReward>> {
        let maybe_block = {
            let consensus_graph = self.consensus_graph();
            let inner = &*consensus_graph.inner.read();
            let epoch_height = match consensus_graph
                .get_height_from_epoch_number(epoch.into())
                .ok()
            {
                None => return Ok(None),
                Some(v) => v,
            };
            let pivot_hash =
                match inner.get_pivot_hash_from_epoch_number(epoch_height).ok()
                {
                    None => return Ok(None),
                    Some(v) => v,
                };
            self.data_man.block_by_hash(&pivot_hash, false)
        };

        if maybe_block.is_none() {
            return Ok(None);
        }
        let block = maybe_block.unwrap();
        if block.block_header.pos_reference().is_none() {
            return Ok(None);
        }
        match self
            .data_man
            .block_by_hash(block.block_header.parent_hash(), false)
        {
            None => Ok(None),
            Some(parent_block) => {
                if parent_block.block_header.pos_reference().is_none() {
                    return Ok(None);
                }
                let block_pos_ref = block.block_header.pos_reference().unwrap();
                let parent_pos_ref =
                    parent_block.block_header.pos_reference().unwrap();

                if block_pos_ref == parent_pos_ref {
                    return Ok(None);
                }

                let hash = HashValue::from_slice(parent_pos_ref.as_bytes())
                    .map_err(|_| internal_error())?;
                let pos_block = self
                    .pos_handler
                    .pos_ledger_db()
                    .get_committed_block_by_hash(&hash)
                    .map_err(|_| internal_error())?;
                let maybe_epoch_rewards =
                    self.data_man.pos_reward_by_pos_epoch(pos_block.epoch);
                if maybe_epoch_rewards.is_none() {
                    return Ok(None);
                }
                let epoch_rewards = maybe_epoch_rewards.unwrap();
                if epoch_rewards.execution_epoch_hash
                    != block.block_header.hash()
                {
                    return Ok(None);
                }
                let reward_info: PoSEpochReward = convert_to_pos_epoch_reward(
                    epoch_rewards,
                    self.network_type,
                )
                .map_err(|_| internal_error())?;
                Ok(Some(reward_info))
            }
        }
    }

    async fn get_vote_params(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<VoteParamsInfo> {
        let epoch = epoch_number.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch, "epoch_num")
            .map_err(into_rpc_err)?;
        let interest_rate = state_db
            .get_global_param::<InterestRate>()
            .map_err(into_rpc_err)?
            / U256::from(BLOCKS_PER_YEAR);
        let pow_base_reward = state_db
            .get_global_param::<PowBaseReward>()
            .map_err(into_rpc_err)?;
        let storage_point_prop = state_db
            .get_system_storage(&storage_point_prop())
            .map_err(into_rpc_err)?;
        let base_fee_share_prop = state_db
            .get_global_param::<BaseFeeProp>()
            .map_err(into_rpc_err)?;
        Ok(VoteParamsInfo {
            pow_base_reward,
            interest_rate,
            storage_point_prop,
            base_fee_share_prop,
        })
    }
}

/// Check balance against transaction helper
pub fn check_balance_against_transaction(
    user_account: Option<Account>, contract_account: Option<Account>,
    is_sponsored: bool, gas_limit: U256, gas_price: U256, storage_limit: U256,
) -> CheckBalanceAgainstTransactionResponse {
    let sponsor_for_gas = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_for_gas)
        .unwrap_or_default();

    let gas_bound: cfx_types::U512 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_gas_bound)
        .unwrap_or_default()
        .into();

    let balance_for_gas: cfx_types::U512 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_balance_for_gas)
        .unwrap_or_default()
        .into();

    let sponsor_for_collateral = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_for_collateral)
        .unwrap_or_default();

    let balance_for_collateral: cfx_types::U512 = contract_account
        .as_ref()
        .map(|a| {
            a.sponsor_info.sponsor_balance_for_collateral
                + a.sponsor_info.unused_storage_points()
        })
        .unwrap_or_default()
        .into();

    let user_balance: cfx_types::U512 =
        user_account.map(|a| a.balance).unwrap_or_default().into();

    let gas_cost_in_drip = gas_limit.full_mul(gas_price);
    let storage_cost_in_drip =
        storage_limit.full_mul(*DRIPS_PER_STORAGE_COLLATERAL_UNIT);

    let will_pay_tx_fee = !is_sponsored
        || sponsor_for_gas.is_zero()
        || (gas_cost_in_drip > gas_bound)
        || (gas_cost_in_drip > balance_for_gas);

    let will_pay_collateral = !is_sponsored
        || sponsor_for_collateral.is_zero()
        || (storage_cost_in_drip > balance_for_collateral);

    let minimum_balance = match (will_pay_tx_fee, will_pay_collateral) {
        (false, false) => 0.into(),
        (true, false) => gas_cost_in_drip,
        (false, true) => storage_cost_in_drip,
        (true, true) => gas_cost_in_drip + storage_cost_in_drip,
    };

    let is_balance_enough = user_balance >= minimum_balance;

    CheckBalanceAgainstTransactionResponse {
        will_pay_tx_fee,
        will_pay_collateral,
        is_balance_enough,
    }
}

#[async_trait]
impl CfxDebugRpcServer for CfxHandler {
    async fn send_transaction(
        &self, tx: TransactionRequest, password: Option<String>,
    ) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendTransaction, tx = {:?}", tx);
        let signed = self
            .prepare_transaction(tx, password)
            .map_err(into_rpc_err)?;
        self.send_transaction_with_signature(signed)
            .map_err(into_rpc_err)
    }

    async fn accounts(&self) -> RpcResult<Vec<RpcAddress>> {
        let accounts: Vec<Address> = self.accounts.accounts().map_err(|e| {
            into_rpc_err(format!(
                "Could not fetch accounts. With error {:?}",
                e
            ))
        })?;
        Ok(accounts
            .into_iter()
            .map(|addr| RpcAddress::try_from_h160(addr, self.network_type))
            .collect::<Result<_, _>>()
            .map_err(|e| into_rpc_err(e))?)
    }

    async fn new_account(&self, password: String) -> RpcResult<RpcAddress> {
        let address =
            self.accounts.new_account(&password.into()).map_err(|e| {
                into_rpc_err(format!(
                    "Could not create account. With error {:?}",
                    e
                ))
            })?;
        RpcAddress::try_from_h160(address, self.network_type)
            .map_err(into_rpc_err)
    }

    async fn unlock_account(
        &self, address: RpcAddress, password: String, duration: Option<U128>,
    ) -> RpcResult<bool> {
        self.check_address_network(address.network)?;
        let account: H160 = address.into();
        let store = self.accounts.clone();

        let duration = match duration {
            None => None,
            Some(duration) => {
                let duration: U128 = duration.into();
                let v = duration.low_u64() as u32;
                if duration != v.into() {
                    return Err(invalid_params_msg("invalid duration number"));
                } else {
                    Some(v)
                }
            }
        };

        let r = match duration {
            Some(0) => {
                store.unlock_account_permanently(account, password.into())
            }
            Some(d) => store.unlock_account_timed(
                account,
                password.into(),
                Duration::from_secs(d.into()),
            ),
            None => store.unlock_account_timed(
                account,
                password.into(),
                Duration::from_secs(300),
            ),
        };
        match r {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("Unable to unlock the account. With error {:?}", err);
                Err(internal_error())
            }
        }
    }

    async fn lock_account(&self, address: RpcAddress) -> RpcResult<bool> {
        self.check_address_network(address.network)?;
        match self.accounts.lock_account(address.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("Unable to lock the account. With error {:?}", err);
                Err(internal_error())
            }
        }
    }

    fn sign(
        &self, data: Bytes, address: RpcAddress, password: Option<String>,
    ) -> RpcResult<H520> {
        self.check_address_network(address.network)?;
        let message = eth_data_hash(data.0);
        let password = password.map(Password::from);
        let signature =
            match self.accounts.sign(address.into(), password, message) {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("Unable to sign the message. With error {:?}", err);
                    return Err(internal_error());
                }
            };
        Ok(H520(signature.into()))
    }

    fn sign_transaction(
        &self, tx: TransactionRequest, password: Option<String>,
    ) -> RpcResult<String> {
        let tx = self.prepare_transaction(tx, password).map_err(|e| {
            invalid_params(
                "tx",
                Some(format!("failed to sign transaction: {:?}", e)),
            )
        })?;
        let raw_tx = rlp::encode(&tx);
        Ok(format!("0x{}", raw_tx.to_hex::<String>()))
    }

    async fn epoch_receipts(
        &self, epoch: BlockHashOrEpochNumber,
        include_eth_receipts: Option<bool>,
    ) -> RpcResult<Option<Vec<Vec<RpcReceipt>>>> {
        info!("RPC Request: cfx_getEpochReceipts({:?})", epoch);

        let hashes = self
            .consensus
            .get_block_hashes_by_epoch_or_block_hash(epoch.into())
            .map_err(into_rpc_err)?;

        let pivot_hash =
            *hashes.last().ok_or(into_rpc_err("Inconsistent state"))?;
        let mut epoch_receipts = vec![];

        for h in hashes {
            epoch_receipts.push(
                match self
                    .prepare_block_receipts(
                        h,
                        pivot_hash,
                        include_eth_receipts.unwrap_or(false),
                    )
                    .map_err(into_rpc_err)?
                {
                    None => return Ok(None),
                    Some(rs) => rs,
                },
            );
        }

        self.check_response_size(&epoch_receipts)
            .map_err(into_rpc_err)?;

        Ok(Some(epoch_receipts))
    }

    async fn account_pending_info(
        &self, address: RpcAddress,
    ) -> RpcResult<Option<AccountPendingInfo>> {
        info!("RPC Request: cfx_getAccountPendingInfo({:?})", address);
        self.check_address_network(address.network)?;

        match self.tx_pool.get_account_pending_info(
            &Address::from(address).with_native_space(),
        ) {
            None => Ok(None),
            Some((
                local_nonce,
                pending_count,
                pending_nonce,
                next_pending_tx,
            )) => Ok(Some(AccountPendingInfo {
                local_nonce: local_nonce.into(),
                pending_count: pending_count.into(),
                pending_nonce: pending_nonce.into(),
                next_pending_tx: next_pending_tx.into(),
            })),
        }
    }

    async fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        info!(
            "RPC Request: cfx_getAccountPendingTransactions(addr={:?}, start_nonce={:?}, limit={:?})",
            address, maybe_start_nonce, maybe_limit
        );
        self.check_address_network(address.network)?;

        let (pending_txs, tx_status, pending_count) = self
            .tx_pool
            .get_account_pending_transactions(
                &Address::from(address).with_native_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.consensus.best_epoch_number(),
            )
            .map_err(into_rpc_err)?;

        Ok(AccountPendingTransactions {
            pending_transactions: pending_txs
                .into_iter()
                .map(|tx| {
                    RpcTransaction::from_signed(&tx, None, self.network_type)
                })
                .collect::<Result<Vec<RpcTransaction>, String>>()
                .map_err(|e| into_rpc_err(e))?,
            first_tx_status: tx_status,
            pending_count: pending_count.into(),
        })
    }
}
