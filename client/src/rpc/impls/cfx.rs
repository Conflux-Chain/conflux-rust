// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use blockgen::BlockGenerator;
use cfx_parameters::staking::COLLATERAL_PER_BYTE;
use cfx_statedb::{StateDbExt, StateDbGetOriginalMethods};
use cfx_types::{
    address_util::AddressUtil, BigEndianHash, H160, H256, H520, U128, U256,
    U512, U64,
};
use cfxcore::{
    block_data_manager::BlockExecutionResultWithEpoch,
    executive::{ExecutionError, ExecutionOutcome, TxDropError},
    rpc_errors::{account_result_to_rpc_result, invalid_params_check},
    state_exposer::STATE_EXPOSER,
    vm, ConsensusGraph, ConsensusGraphTrait, PeerInfo, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use delegate::delegate;
use jsonrpc_core::{BoxFuture, Error as JsonRpcError, Result as JsonRpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use parking_lot::Mutex;
use primitives::{
    filter::Filter, transaction::Action::Call, Account, SignedTransaction,
    StorageKey, StorageValue, TransactionWithSignature,
};
use random_crash::*;
use rlp::Rlp;
use rustc_hex::ToHex;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
use txgen::{DirectTransactionGenerator, TransactionGenerator};
// To convert from RpcResult to BoxFuture by delegate! macro automatically.
use crate::{
    common::delegate_convert,
    rpc::{
        error_codes::{
            call_execution_error, invalid_params,
            request_rejected_in_catch_up_mode,
        },
        impls::{common::RpcImpl as CommonImpl, RpcImplConfiguration},
        traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
        types::{
            sign_call, Account as RpcAccount, BlameInfo, Block as RpcBlock,
            BlockHashOrEpochNumber, Bytes, CallRequest,
            CheckBalanceAgainstTransactionResponse, ConsensusGraphStates,
            EpochNumber, EstimateGasAndCollateralResponse, Filter as RpcFilter,
            Log as RpcLog, PackedOrExecuted, Receipt as RpcReceipt,
            RewardInfo as RpcRewardInfo, SendTxRequest,
            SponsorInfo as RpcSponsorInfo, Status as RpcStatus,
            StorageRoot as RpcStorageRoot, SyncGraphStates,
            Transaction as RpcTransaction, TxPoolPendingInfo, TxWithPoolInfo,
        },
        RpcResult,
    },
};
use lazy_static::lazy_static;
use metrics::{register_timer_with_group, ScopeTimer, Timer};

lazy_static! {
    static ref SEND_RAW_TX_TIMER: Arc<dyn Timer> =
        register_timer_with_group("rpc", "rpc:sendRawTransaction");
    static ref GET_LOGS_TIMER: Arc<dyn Timer> =
        register_timer_with_group("rpc", "rpc:getLogs");
}

pub struct RpcImpl {
    config: RpcImplConfiguration,
    pub consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    block_gen: Arc<BlockGenerator>,
    tx_pool: SharedTransactionPool,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    accounts: Arc<AccountProvider>,
}

impl RpcImpl {
    pub fn new(
        consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        block_gen: Arc<BlockGenerator>, tx_pool: SharedTransactionPool,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
        config: RpcImplConfiguration, accounts: Arc<AccountProvider>,
    ) -> Self
    {
        RpcImpl {
            consensus,
            sync,
            block_gen,
            tx_pool,
            maybe_txgen,
            maybe_direct_txgen,
            config,
            accounts,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    fn code(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState);
        info!(
            "RPC Request: cfx_getCode address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num.clone().into())?;
        let acc = invalid_params_check(
            "address",
            state_db.get_account(&address)?.ok_or(format!(
                "Account[{:?}] epoch_number[{:?}] does not exist",
                address, epoch_num,
            )),
        )?;

        Ok(Bytes::new(
            match state_db.get_code(&address, &acc.code_hash) {
                Ok(Some(code)) => (*code.code).clone(),
                _ => vec![],
            },
        ))
    }

    fn balance(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let acc = state_db.get_account(&address)?;

        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    fn admin(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<Option<H160>> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let acc = state_db.get_account(&address)?;

        Ok(acc.map(|acc| acc.admin.into()))
    }

    fn sponsor_info(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcSponsorInfo> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let acc = state_db.get_account(&address)?;

        Ok(RpcSponsorInfo::new(
            acc.map(|acc| acc.sponsor_info.clone()).unwrap_or_default(),
        ))
    }

    fn staking_balance(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let acc = state_db.get_account(&address)?;

        Ok(acc.map_or(U256::zero(), |acc| acc.staking_balance).into())
    }

    fn collateral_for_storage(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let acc = state_db.get_account(&address)?;

        Ok(acc
            .map_or(U256::zero(), |acc| acc.collateral_for_storage)
            .into())
    }

    /// Return account related states of the given account
    fn account(
        &self, address: H160, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAccount address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;

        Ok(RpcAccount::new(match state_db.get_account(&address)? {
            Some(t) => t,
            None => account_result_to_rpc_result(
                "address",
                Account::new_empty_with_balance(
                    &address,
                    &U256::zero(), /* balance */
                    &U256::zero(), /* nonce */
                ),
            )?,
        }))
    }

    /// Returns interest rate of the given epoch
    fn interest_rate(&self, epoch_num: Option<EpochNumber>) -> RpcResult<U256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;

        Ok(state_db.get_annual_interest_rate()?.into())
    }

    /// Returns accumulate interest rate of the given epoch
    fn accumulate_interest_rate(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;

        Ok(state_db.get_accumulate_interest_rate()?.into())
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        let _timer = ScopeTimer::time_scope(SEND_RAW_TX_TIMER.as_ref());
        info!("RPC Request: cfx_sendRawTransaction len={:?}", raw.0.len());
        debug!("RawTransaction bytes={:?}", raw);

        // FIXME: input parse error.
        let tx = Rlp::new(&raw.into_vec()).as_val().map_err(|err| {
            invalid_params("raw", format!("Error: {:?}", err))
        })?;

        self.send_transaction_with_signature(tx)
    }

    fn storage_at(
        &self, address: H160, position: H256, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<H256>> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            address, position, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;
        let key = StorageKey::new_storage_key(&address, position.as_ref());

        Ok(match state_db.get::<StorageValue>(key)? {
            Some(entry) => Some(H256::from_uint(&entry.value).into()),
            None => None,
        })
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> RpcResult<H256> {
        if let Call(address) = &tx.transaction.action {
            if !address.is_valid_address() {
                bail!(invalid_params("tx", "Sending transactions to invalid address. The first four bits must be 0x0 (built-in/reserved), 0x1 (user-account), or 0x8 (contract)."));
            }
        }
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

    // FIXME: understand this rpc..
    fn prepare_transaction(
        &self, mut tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<TransactionWithSignature> {
        let consensus_graph = self.consensus_graph();

        if tx.nonce.is_none() {
            let nonce = consensus_graph
                .next_nonce(
                    tx.from.clone().into(),
                    BlockHashOrEpochNumber::EpochNumber(
                        EpochNumber::LatestState,
                    )
                    .into_primitive(),
                )
                .map_err(|e| {
                    invalid_params(
                        "tx",
                        format!("failed to send transaction: {:?}", e),
                    )
                })?;
            tx.nonce.replace(nonce.into());
            debug!("after loading nonce in latest state, tx = {:?}", tx);
        }

        let epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        let tx = tx
            .sign_with(epoch_height, chain_id, password, self.accounts.clone())
            .map_err(|e| {
                invalid_params(
                    "tx",
                    format!("failed to send transaction: {:?}", e),
                )
            })?;

        Ok(tx)
    }

    fn send_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendTransaction, tx = {:?}", tx);

        self.prepare_transaction(tx, password)
            .and_then(|tx| self.send_transaction_with_signature(tx))
    }

    pub fn sign_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<String> {
        let tx = self.prepare_transaction(tx, password).map_err(|e| {
            invalid_params("tx", format!("failed to sign transaction: {:?}", e))
        })?;
        let raw_tx = rlp::encode(&tx);
        Ok(format!("0x{}", raw_tx.to_hex()))
    }

    fn storage_root(
        &self, address: H160, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcStorageRoot>> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStorageRoot address={:?} epoch={:?}",
            address, epoch_num
        );

        let state_db =
            self.consensus.get_state_db_by_epoch_number(epoch_num)?;

        Ok(match state_db.get_original_storage_root(&address)? {
            Some(storage_root) => {
                Some(RpcStorageRoot::from_primitive(storage_root))
            }
            None => None,
        })
    }

    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes> {
        info!(
            "RPC Request: send_usable_genesis_accounts start from {:?}",
            account_start_index
        );
        match self.maybe_txgen.as_ref() {
            None => {
                // FIXME: method_not_found
                let mut rpc_error = JsonRpcError::method_not_found();
                rpc_error.message = "send_usable_genesis_accounts only allowed in test or dev mode with txgen set.".into();
                bail!(rpc_error)
            }
            Some(txgen) => {
                txgen.set_genesis_accounts_start_index(account_start_index);
                Ok(Bytes::new("1".into()))
            }
        }
    }

    pub fn transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<RpcTransaction>> {
        let hash: H256 = hash.into();
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        if let Some(info) = self.consensus.get_transaction_info_by_hash(&hash) {
            let (tx, tx_index, maybe_executed) = info;
            let packed_or_executed = match maybe_executed {
                None => PackedOrExecuted::Packed(tx_index),
                Some((receipt, prior_gas_used)) => {
                    PackedOrExecuted::Executed(RpcReceipt::new(
                        tx.clone(),
                        receipt,
                        tx_index,
                        prior_gas_used,
                        None,
                        None,
                    ))
                }
            };
            let rpc_tx =
                RpcTransaction::from_signed(&tx, Some(packed_or_executed));
            return Ok(Some(rpc_tx));
        }

        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            let rpc_tx = RpcTransaction::from_signed(&tx, None);
            return Ok(Some(rpc_tx));
        }

        Ok(None)
    }

    fn prepare_receipt(&self, hash: H256) -> RpcResult<Option<RpcReceipt>> {
        // Get a consistent view from ConsensusInner
        let consensus_graph = self.consensus_graph();

        let maybe_results =
            consensus_graph.get_transaction_receipt_and_block_info(&hash);
        let (
            BlockExecutionResultWithEpoch(epoch_hash, execution_result),
            address,
            maybe_state_root,
        ) = match maybe_results {
            None => return Ok(None),
            Some(result_tuple) => result_tuple,
        };

        let epoch_block_header = self
            .consensus
            .get_data_manager()
            .block_header_by_hash(&epoch_hash)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?;
        let epoch_number = epoch_block_header.height();
        if epoch_number > consensus_graph.best_executed_state_epoch_number() {
            // The receipt is only visible to optimistic execution.
            return Ok(None);
        }

        // Operations below will not involve the status of ConsensusInner
        let block = self
            .consensus
            .get_data_manager()
            .block_by_hash(&address.block_hash, true)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?;
        let transaction = block
            .transactions
            .get(address.index)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?
            .as_ref()
            .clone();
        let receipt = execution_result
            .block_receipts
            .receipts
            .get(address.index)
            // FIXME: server error, client should request another server.
            .ok_or("Inconsistent state")?
            .clone();
        let prior_gas_used = if address.index == 0 {
            U256::zero()
        } else {
            let prior_receipt = execution_result
                .block_receipts
                .receipts
                .get(address.index - 1)
                // FIXME: server error, client should request another server.
                .ok_or("Inconsistent state")?
                .clone();
            prior_receipt.accumulated_gas_used
        };
        let rpc_receipt = RpcReceipt::new(
            transaction,
            receipt,
            address,
            prior_gas_used,
            Some(epoch_number),
            maybe_state_root,
        );
        Ok(Some(rpc_receipt))
    }

    fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt({:?})", hash);
        self.prepare_receipt(hash)
    }

    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>> {
        info!("RPC Request: generate({:?})", num_blocks);
        let mut hashes = Vec::new();
        for _i in 0..num_blocks {
            hashes.push(
                self.block_gen.generate_block(
                    0,
                    self.sync
                        .get_synchronization_graph()
                        .verification_config
                        .max_block_size_in_bytes,
                    vec![],
                ),
            );
        }
        Ok(hashes)
    }

    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>,
    ) -> RpcResult<H256>
    {
        info!(
            "RPC Request: generate_fixed_block({:?}, {:?}, {:?}, {:?})",
            parent_hash, referee, num_txs, difficulty
        );
        Ok(self.block_gen.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty.unwrap_or(0),
            adaptive,
        )?)
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_one_block()");
        Ok(self
            .block_gen
            .generate_block(num_txs, block_size_limit, vec![]))
    }

    fn generate_one_block_with_direct_txgen(
        &self, num_txs: usize, mut block_size_limit: usize,
        num_txs_simple: usize, num_txs_erc20: usize,
    ) -> RpcResult<H256>
    {
        info!("RPC Request: generate_one_block_with_direct_txgen()");

        let block_gen = &self.block_gen;
        match self.maybe_direct_txgen.as_ref() {
            None => {
                // FIXME: create helper function.
                let mut rpc_error = JsonRpcError::method_not_found();
                rpc_error.message = "generate_one_block_with_direct_txgen only allowed in test or dev mode.".into();
                bail!(rpc_error)
            }
            Some(direct_txgen) => {
                let generated_transactions =
                    direct_txgen.lock().generate_transactions(
                        &mut block_size_limit,
                        num_txs_simple,
                        num_txs_erc20,
                        &self.consensus.get_config().chain_id,
                    );

                Ok(block_gen.generate_block(
                    num_txs,
                    block_size_limit,
                    generated_transactions,
                ))
            }
        }
    }

    fn generate_custom_block(
        &self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes,
        adaptive: Option<bool>,
    ) -> RpcResult<H256>
    {
        info!("RPC Request: generate_custom_block()");

        let transactions = self.decode_raw_txs(raw_txs, 0)?;

        Ok(self.block_gen.generate_custom_block_with_parent(
            parent_hash,
            referee,
            transactions,
            adaptive.unwrap_or(false),
        )?)
    }

    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256>
    {
        let transactions = self.decode_raw_txs(raw, 0)?;
        Ok(self.block_gen.generate_block_with_nonce_and_timestamp(
            parent,
            referees,
            transactions,
            nonce,
            timestamp,
            adaptive,
        )?)
    }

    fn decode_raw_txs(
        &self, raw_txs: Bytes, tx_data_len: usize,
    ) -> RpcResult<Vec<Arc<SignedTransaction>>> {
        let txs: Vec<TransactionWithSignature> =
            Rlp::new(&raw_txs.into_vec()).as_list().map_err(|err| {
                invalid_params("raw_txs", format!("Decode error: {:?}", err))
            })?;

        let mut transactions = Vec::new();

        for tx in txs {
            match tx.recover_public() {
                Ok(public) => {
                    let mut signed_tx = SignedTransaction::new(public, tx);
                    if tx_data_len > 0 {
                        signed_tx.transaction.transaction.unsigned.data =
                            vec![0; tx_data_len];
                    }
                    transactions.push(Arc::new(signed_tx));
                }
                Err(e) => {
                    bail!(invalid_params(
                        &format!("raw_txs, tx {:?}", tx),
                        format!("Recover public error: {:?}", e),
                    ));
                }
            }
        }

        Ok(transactions)
    }

    fn generate_block_with_fake_txs(
        &self, raw_txs_without_data: Bytes, adaptive: Option<bool>,
        tx_data_len: Option<usize>,
    ) -> RpcResult<H256>
    {
        let transactions = self
            .decode_raw_txs(raw_txs_without_data, tx_data_len.unwrap_or(0))?;
        Ok(self.block_gen.generate_custom_block(transactions, adaptive))
    }

    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256> {
        Ok(self.block_gen.generate_block_with_blame_info(
            num_txs,
            block_size_limit,
            vec![],
            blame_info.blame.map(|x| x.as_u32()),
            blame_info.deferred_state_root.map(|x| x.into()),
            blame_info.deferred_receipts_root.map(|x| x.into()),
            blame_info.deferred_logs_bloom_hash.map(|x| x.into()),
        ))
    }

    fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>> {
        let _timer = ScopeTimer::time_scope(GET_LOGS_TIMER.as_ref());
        let consensus_graph = self.consensus_graph();

        info!("RPC Request: cfx_getLogs({:?})", filter);
        let mut filter: Filter = filter.into_primitive()?;

        // If max_limit is set, the value in `filter` will be modified to
        // satisfy this limitation to avoid loading too many blocks
        // TODO Should the response indicate that the filter is modified?
        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if filter.limit.is_none() || filter.limit.unwrap() > max_limit {
                filter.limit = Some(max_limit);
            }
        }

        Ok(consensus_graph
            .logs(filter)?
            .iter()
            .cloned()
            .map(RpcLog::from)
            .collect())
    }

    fn get_block_reward_info(
        &self, epoch: EpochNumber,
    ) -> RpcResult<Vec<RpcRewardInfo>> {
        info!(
            "RPC Request: cfx_getBlockRewardInfo epoch_number={:?}",
            epoch
        );

        let blocks = self.consensus.get_block_hashes_by_epoch(epoch.into())?;

        let mut ret = Vec::new();
        for b in blocks {
            if let Some(reward_result) = self
                .consensus
                .get_data_manager()
                .block_reward_result_by_hash(&b)
            {
                if let Some(block_header) =
                    self.consensus.get_data_manager().block_header_by_hash(&b)
                {
                    ret.push(RpcRewardInfo::new(
                        b,
                        block_header.author().clone(),
                        reward_result,
                    ));
                }
            }
        }
        Ok(ret)
    }

    fn call(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
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

    fn estimate_gas_and_collateral(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
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
            ) => executed,
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                bail!(call_execution_error(
                    format! {"Can not estimate: transaction execution failed, \
                     all gas will be charged (execution error: {:?})", e}.into(),
                    format! {"{:?}", e}.into_bytes()
                ))
            }
            ExecutionOutcome::Finished(executed) => executed,
        };
        let mut storage_collateralized = 0;
        for storage_change in &executed.storage_collateralized {
            storage_collateralized += storage_change.amount;
        }
        let response = EstimateGasAndCollateralResponse {
            gas_used: executed.gas_used.into(),
            storage_collateralized: storage_collateralized.into(),
        };
        Ok(response)
    }

    fn check_balance_against_transaction(
        &self, account_addr: H160, contract_addr: H160, gas_limit: U256,
        gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>,
    ) -> RpcResult<CheckBalanceAgainstTransactionResponse>
    {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();
        if storage_limit > U256::from(std::u64::MAX) {
            bail!(JsonRpcError::invalid_params(format!("storage_limit has to be within the range of u64 but {} supplied!", storage_limit)));
        }

        let state = self.consensus.get_state_by_epoch_number(epoch)?;
        let gas_cost = gas_limit.full_mul(gas_price);
        let mut gas_sponsored = false;
        let mut storage_sponsored = false;
        if state.check_commission_privilege(&contract_addr, &account_addr)? {
            // No need to check for gas sponsor account existence.
            gas_sponsored = gas_cost
                <= U512::from(state.sponsor_gas_bound(&contract_addr)?);
            storage_sponsored =
                state.sponsor_for_collateral(&contract_addr)?.is_some();
        }
        let gas_sponsor_balance = if gas_sponsored {
            U512::from(state.sponsor_balance_for_gas(&contract_addr)?)
        } else {
            0.into()
        };
        let will_pay_tx_fee = !gas_sponsored || gas_sponsor_balance < gas_cost;

        let storage_limit_in_drip = storage_limit * *COLLATERAL_PER_BYTE;
        let storage_sponsor_balance = if storage_sponsored {
            state.sponsor_balance_for_collateral(&contract_addr)?
        } else {
            0.into()
        };

        let will_pay_collateral = !storage_sponsored
            || storage_limit_in_drip > storage_sponsor_balance;

        let balance = state.balance(&account_addr)?;
        let minimum_balance = if will_pay_tx_fee { gas_cost } else { 0.into() };
        let is_balance_enough = U512::from(balance) >= minimum_balance;

        Ok(CheckBalanceAgainstTransactionResponse {
            will_pay_tx_fee,
            will_pay_collateral,
            is_balance_enough,
        })
    }

    fn exec_transaction(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<ExecutionOutcome> {
        let consensus_graph = self.consensus_graph();
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);

        let best_epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        let signed_tx = sign_call(best_epoch_height, chain_id, request);
        trace!("call tx {:?}", signed_tx);
        consensus_graph.call_virtual(&signed_tx, epoch.into())
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        Ok(self.sync.current_sync_phase().name().into())
    }

    /// Return the pivot chain block hashes in `height_range` (inclusive) and
    /// their subtree weight. If it's none, return all pivot chain from
    /// `cur_era_genesis` to chain tip.
    ///
    /// Note that this should note query blocks before `cur_era_genesis`.
    fn get_pivot_chain_and_weight(
        &self, height_range: Option<(u64, u64)>,
    ) -> RpcResult<Vec<(H256, U256)>> {
        let consensus_graph = self.consensus_graph();
        Ok(consensus_graph
            .inner
            .read()
            .get_pivot_chain_and_weight(height_range)?)
    }

    fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)> {
        let commitment = self
            .consensus
            .get_data_manager()
            .get_epoch_execution_commitment(&block_hash)
            .ok_or(JsonRpcError::invalid_params(
                "No receipts root. Possibly never pivot?".to_owned(),
            ))?;
        Ok((
            commitment.receipts_root.clone().into(),
            commitment
                .state_root_with_aux_info
                .state_root
                .compute_state_root_hash(),
        ))
    }

    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()> {
        self.sync.expire_block_gc(timeout);
        Ok(())
    }

    pub fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates> {
        let consensus_graph_states =
            STATE_EXPOSER.consensus_graph.lock().retrieve();
        Ok(ConsensusGraphStates::new(consensus_graph_states))
    }

    pub fn sync_graph_state(&self) -> RpcResult<SyncGraphStates> {
        let sync_graph_states = STATE_EXPOSER.sync_graph.lock().retrieve();
        Ok(SyncGraphStates::new(sync_graph_states))
    }

    /// Return (block_info.status, state_valid)
    /// Return Error if either field is missing
    pub fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)> {
        let consensus_graph = self.consensus_graph();
        let status = consensus_graph
            .data_man
            .local_block_info_by_hash(&block_hash)
            // FIXME: invalid_params?
            .ok_or(invalid_params("block_hash", "No block status"))?
            .get_status();
        let state_valid = consensus_graph
            .inner
            .read()
            .block_node(&block_hash)
            .ok_or(invalid_params("block_hash", "No block in consensus"))?
            .data
            .state_valid
            .ok_or(invalid_params("block_hash", "No state_valid"))?;
        Ok((status.to_db_status(), state_valid))
    }

    pub fn set_db_crash(
        &self, crash_probability: f64, crash_exit_code: i32,
    ) -> RpcResult<()> {
        if crash_probability == 0.0 {
            *CRASH_EXIT_PROBABILITY.lock() = None;
        } else {
            *CRASH_EXIT_PROBABILITY.lock() = Some(crash_probability);
        }
        *CRASH_EXIT_CODE.lock() = crash_exit_code;
        Ok(())
    }
}

#[allow(dead_code)]
pub struct CfxHandler {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl CfxHandler {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        CfxHandler { common, rpc_impl }
    }
}

impl Cfx for CfxHandler {
    delegate! {
        to self.common {
            fn best_block_hash(&self) -> JsonRpcResult<H256>;
            fn block_by_epoch_number(
                &self, epoch_num: EpochNumber, include_txs: bool) -> JsonRpcResult<Option<RpcBlock>>;
            fn block_by_hash_with_pivot_assumption(
                &self, block_hash: H256, pivot_hash: H256, epoch_number: U64)
                -> JsonRpcResult<RpcBlock>;
            fn block_by_hash(&self, hash: H256, include_txs: bool)
                -> JsonRpcResult<Option<RpcBlock>>;
            fn confirmation_risk_by_hash(&self, block_hash: H256) -> JsonRpcResult<Option<U256>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<U256>;
            fn gas_price(&self) -> JsonRpcResult<U256>;
            fn next_nonce(&self, address: H160, num: Option<BlockHashOrEpochNumber>)
                -> JsonRpcResult<U256>;
            fn get_status(&self) -> JsonRpcResult<RpcStatus>;
            fn get_client_version(&self) -> JsonRpcResult<String>;
        }

        to self.rpc_impl {
            fn code(&self, addr: H160, epoch_number: Option<EpochNumber>) -> BoxFuture<Bytes>;
            fn account(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn interest_rate(&self, num: Option<EpochNumber>) -> JsonRpcResult<U256>;
            fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> JsonRpcResult<U256>;
            fn admin(&self, address: H160, num: Option<EpochNumber>)
                -> BoxFuture<Option<H160>>;
            fn sponsor_info(&self, address: H160, num: Option<EpochNumber>)
                -> BoxFuture<RpcSponsorInfo>;
            fn balance(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn staking_balance(&self, address: H160, num: Option<EpochNumber>)
                -> BoxFuture<U256>;
            fn collateral_for_storage(&self, address: H160, num: Option<EpochNumber>)
                -> BoxFuture<U256>;
            fn call(&self, request: CallRequest, epoch: Option<EpochNumber>)
                -> JsonRpcResult<Bytes>;
            fn estimate_gas_and_collateral(
                &self, request: CallRequest, epoch_number: Option<EpochNumber>)
                -> JsonRpcResult<EstimateGasAndCollateralResponse>;
            fn check_balance_against_transaction(
                &self, account_addr: H160, contract_addr: H160, gas_limit: U256, gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>,
            ) -> JsonRpcResult<CheckBalanceAgainstTransactionResponse>;
            fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
            fn get_block_reward_info(&self, num: EpochNumber) -> JsonRpcResult<Vec<RpcRewardInfo>>;
            fn send_raw_transaction(&self, raw: Bytes) -> JsonRpcResult<H256>;
            fn storage_at(&self, addr: H160, pos: H256, epoch_number: Option<EpochNumber>)
                -> BoxFuture<Option<H256>>;
            fn transaction_by_hash(&self, hash: H256) -> BoxFuture<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: H256) -> BoxFuture<Option<RpcReceipt>>;
            fn storage_root(&self, address: H160, epoch_num: Option<EpochNumber>) -> BoxFuture<Option<RpcStorageRoot>>;
        }
    }
}

#[allow(dead_code)]
pub struct TestRpcImpl {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl TestRpcImpl {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        TestRpcImpl { common, rpc_impl }
    }
}

impl TestRpc for TestRpcImpl {
    delegate! {
        to self.common {
            fn add_latency(&self, id: NodeId, latency_ms: f64) -> JsonRpcResult<()>;
            fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> JsonRpcResult<()>;
            fn chain(&self) -> JsonRpcResult<Vec<RpcBlock>>;
            fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> JsonRpcResult<()>;
            fn get_block_count(&self) -> JsonRpcResult<u64>;
            fn get_goodput(&self) -> JsonRpcResult<String>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> JsonRpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> JsonRpcResult<Vec<PeerInfo>>;
            fn say_hello(&self) -> JsonRpcResult<String>;
            fn stop(&self) -> JsonRpcResult<()>;
            fn save_node_db(&self) -> JsonRpcResult<()>;
        }

        to self.rpc_impl {
            fn expire_block_gc(&self, timeout: u64) -> JsonRpcResult<()>;
            fn generate_block_with_blame_info(
                &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> JsonRpcResult<H256>;
            fn generate_block_with_fake_txs(
                &self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>)
                -> JsonRpcResult<H256>;
            fn generate_custom_block(
                &self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>)
                -> JsonRpcResult<H256>;
            fn get_pivot_chain_and_weight(&self, height_range: Option<(u64, u64)>) -> JsonRpcResult<Vec<(H256, U256)>>;
            fn get_executed_info(&self, block_hash: H256) -> JsonRpcResult<(H256, H256)> ;
            fn generate_fixed_block(
                &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>)
                -> JsonRpcResult<H256>;
            fn generate_one_block_with_direct_txgen(
                &self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize)
                -> JsonRpcResult<H256>;
            fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> JsonRpcResult<H256>;
            fn generate_block_with_nonce_and_timestamp(
                &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256, timestamp: u64, adaptive: bool)
                -> JsonRpcResult<H256>;
            fn generate_empty_blocks(&self, num_blocks: usize) -> JsonRpcResult<Vec<H256>>;
            fn get_block_status(&self, block_hash: H256) -> JsonRpcResult<(u8, bool)>;
            fn send_usable_genesis_accounts(& self, account_start_index: usize) -> JsonRpcResult<Bytes>;
            fn set_db_crash(&self, crash_probability: f64, crash_exit_code: i32) -> JsonRpcResult<()>;
        }
    }
}

pub struct LocalRpcImpl {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl LocalRpcImpl {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        LocalRpcImpl { common, rpc_impl }
    }
}

impl LocalRpc for LocalRpcImpl {
    delegate! {
        to self.common {
            fn clear_tx_pool(&self) -> JsonRpcResult<()>;
            fn net_node(&self, id: NodeId) -> JsonRpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>)
                -> JsonRpcResult<bool>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> JsonRpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> JsonRpcResult<throttling::Service>;
            fn tx_inspect(&self, hash: H256) -> JsonRpcResult<TxWithPoolInfo>;
            fn txpool_content(&self, address: Option<H160>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txs_from_pool(&self, address: Option<H160>) -> JsonRpcResult<Vec<RpcTransaction>>;
            fn txpool_inspect(&self, address: Option<H160>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> JsonRpcResult<BTreeMap<String, usize>>;
            fn accounts(&self) -> JsonRpcResult<Vec<H160>>;
            fn new_account(&self, password: String) -> JsonRpcResult<H160>;
            fn unlock_account(
                &self, address: H160, password: String, duration: Option<U128>)
                -> JsonRpcResult<bool>;
            fn lock_account(&self, address: H160) -> JsonRpcResult<bool>;
            fn sign(&self, data: Bytes, address: H160, password: Option<String>)
                -> JsonRpcResult<H520>;
            fn tx_inspect_pending(&self, address: H160) -> JsonRpcResult<TxPoolPendingInfo>;

        }

        to self.rpc_impl {
            fn current_sync_phase(&self) -> JsonRpcResult<String>;
            fn consensus_graph_state(&self) -> JsonRpcResult<ConsensusGraphStates>;
            fn sync_graph_state(&self) -> JsonRpcResult<SyncGraphStates>;
            fn send_transaction(
                &self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<H256>;
            fn sign_transaction(&self, tx: SendTxRequest, password: Option<String>) -> JsonRpcResult<String>;
        }
    }
}
