// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    call_request::rpc_call_request_network, errors::check_rpc_address_network,
    pos::PoSEpochReward, PoSEconomics, RpcAddress, SponsorInfo,
    TokenSupplyInfo, VoteParamsInfo,
};
use blockgen::BlockGenerator;
use cfx_state::state_trait::StateOpsTrait;
use cfx_statedb::StateDbExt;
use cfx_types::{
    Address, AddressSpaceUtil, BigEndianHash, Space, H256, H520, U128, U256,
    U64,
};
use cfxcore::{
    executive::{ExecutionError, ExecutionOutcome, TxDropError},
    rpc_errors::{account_result_to_rpc_result, invalid_params_check},
    state_exposer::STATE_EXPOSER,
    vm, ConsensusGraph, ConsensusGraphTrait, PeerInfo, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use delegate::delegate;
use diem_types::transaction::TransactionPayload;
use jsonrpc_core::{BoxFuture, Error as JsonRpcError, Result as JsonRpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use parking_lot::Mutex;
use primitives::{
    filter::LogFilter, Account, Block, BlockReceipts, DepositInfo,
    SignedTransaction, StorageKey, StorageRoot, StorageValue, Transaction,
    TransactionIndex, TransactionOutcome, TransactionWithSignature,
    VoteStakeInfo,
};
use random_crash::*;
use rlp::Rlp;
use rustc_hex::ToHex;
use std::{
    collections::BTreeMap, net::SocketAddr, sync::Arc, thread, time::Duration,
};
use txgen::{DirectTransactionGenerator, TransactionGenerator};
// To convert from RpcResult to BoxFuture by delegate! macro automatically.
use crate::{
    common::delegate_convert,
    rpc::{
        error_codes::{
            call_execution_error, invalid_params, pivot_assumption_failed,
            request_rejected_in_catch_up_mode,
        },
        impls::{
            common::{self, RpcImpl as CommonImpl},
            RpcImplConfiguration,
        },
        traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
        types::{
            pos::Block as PosBlock, sign_call, Account as RpcAccount,
            AccountPendingInfo, AccountPendingTransactions, BlameInfo,
            Block as RpcBlock, BlockHashOrEpochNumber, Bytes, CallRequest,
            CfxRpcLogFilter, CheckBalanceAgainstTransactionResponse,
            ConsensusGraphStates, EpochNumber,
            EstimateGasAndCollateralResponse, Log as RpcLog, PackedOrExecuted,
            Receipt as RpcReceipt, RewardInfo as RpcRewardInfo, SendTxRequest,
            Status as RpcStatus, SyncGraphStates,
            Transaction as RpcTransaction,
        },
        RpcResult,
    },
};
use cfx_addr::Network;
use cfx_parameters::{
    consensus_internal::REWARD_EPOCH_COUNT, staking::BLOCKS_PER_YEAR,
};
use cfx_storage::state::StateDbGetOriginalMethods;
use cfxcore::{
    consensus::{MaybeExecutedTxExtraInfo, TransactionInfo},
    consensus_parameters::DEFERRED_STATE_EPOCH_COUNT,
    executive::{revert_reason_decode, EstimateRequest},
    observer::ErrorUnwind,
    spec::genesis::{
        genesis_contract_address_four_year, genesis_contract_address_two_year,
    },
    state::State,
};
use diem_types::account_address::AccountAddress;
use serde::Serialize;

#[derive(Debug)]
pub(crate) struct BlockExecInfo {
    pub(crate) block_receipts: Arc<BlockReceipts>,
    pub(crate) block: Arc<Block>,
    pub(crate) epoch_number: u64,
    pub(crate) maybe_state_root: Option<H256>,
    pub(crate) pivot_hash: H256,
}

pub struct RpcImpl {
    pub config: RpcImplConfiguration,
    pub consensus: SharedConsensusGraph,
    pub sync: SharedSynchronizationService,
    block_gen: Arc<BlockGenerator>,
    pub tx_pool: SharedTransactionPool,
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

    fn check_address_network(&self, network: Network) -> RpcResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(
                Some(network),
                self.sync.network.get_network_type(),
            ),
        )
    }

    fn code(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        self.check_address_network(address.network)?;
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCode address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

        let address = address.hex_address.with_native_space();

        let code = match state_db.get_account(&address)? {
            Some(acc) => match state_db.get_code(&address, &acc.code_hash)? {
                Some(code) => (*code.code).clone(),
                _ => vec![],
            },
            None => vec![],
        };

        Ok(Bytes::new(code))
    }

    fn balance(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc =
            state_db.get_account(&address.hex_address.with_native_space())?;

        Ok(acc.map_or(U256::zero(), |acc| acc.balance).into())
    }

    fn admin(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcAddress>> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

        match state_db.get_account(&address.hex_address.with_native_space())? {
            None => Ok(None),
            Some(acc) => {
                Ok(Some(RpcAddress::try_from_h160(acc.admin, network)?))
            }
        }
    }

    fn sponsor_info(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<SponsorInfo> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;

        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

        match state_db.get_account(&address.hex_address.with_native_space())? {
            None => Ok(SponsorInfo::default(network)?),
            Some(acc) => Ok(SponsorInfo::try_from(acc.sponsor_info, network)?),
        }
    }

    fn staking_balance(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc =
            state_db.get_account(&address.hex_address.with_native_space())?;

        Ok(acc.map_or(U256::zero(), |acc| acc.staking_balance).into())
    }

    fn deposit_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Vec<DepositInfo>> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getDepositList address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

        match state_db
            .get_deposit_list(&address.hex_address.with_native_space())?
        {
            None => Ok(vec![]),
            Some(deposit_list) => Ok(deposit_list.0),
        }
    }

    fn vote_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Vec<VoteStakeInfo>> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getVoteList address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;

        match state_db
            .get_vote_list(&address.hex_address.with_native_space())?
        {
            None => Ok(vec![]),
            Some(vote_list) => Ok(vote_list.0),
        }
    }

    fn collateral_for_storage(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.check_address_network(address.network)?;
        let epoch_num = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "num")?;
        let acc =
            state_db.get_account(&address.hex_address.with_native_space())?;

        Ok(acc
            .map_or(U256::zero(), |acc| acc.collateral_for_storage)
            .into())
    }

    /// Return account related states of the given account
    fn account(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        self.check_address_network(address.network)?;
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;

        info!(
            "RPC Request: cfx_getAccount address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let address = &address.hex_address;

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;

        let account =
            match state_db.get_account(&address.with_native_space())? {
                Some(t) => t,
                None => account_result_to_rpc_result(
                    "address",
                    Ok(Account::new_empty_with_balance(
                        &address.with_native_space(),
                        &U256::zero(), /* balance */
                        &U256::zero(), /* nonce */
                    )),
                )?,
            };

        Ok(RpcAccount::try_from(account, network)?)
    }

    /// Returns interest rate of the given epoch
    fn interest_rate(&self, epoch_num: Option<EpochNumber>) -> RpcResult<U256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;

        Ok(state_db.get_annual_interest_rate()?.into())
    }

    /// Returns accumulate interest rate of the given epoch
    fn accumulate_interest_rate(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;

        Ok(state_db.get_accumulate_interest_rate()?.into())
    }

    /// Returns accumulate interest rate of the given epoch
    fn pos_economics(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<PoSEconomics> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;

        Ok(PoSEconomics {
            total_pos_staking_tokens: state_db
                .get_total_pos_staking_tokens()?,
            distributable_pos_interest: state_db
                .get_distributable_pos_interest()?,
            last_distribute_block: U64::from(
                state_db.get_last_distribute_block()?,
            ),
        })
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendRawTransaction len={:?}", raw.0.len());
        debug!("RawTransaction bytes={:?}", raw);

        let tx: TransactionWithSignature =
            invalid_params_check("raw", Rlp::new(&raw.into_vec()).as_val())?;

        if tx.recover_public().is_err() {
            bail!(invalid_params(
                "tx",
                "Can not recover pubkey for Ethereum like tx"
            ));
        }

        let r = self.send_transaction_with_signature(tx);
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

    fn storage_at(
        &self, address: RpcAddress, position: U256,
        epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<H256>>
    {
        self.check_address_network(address.network)?;
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            address, position, epoch_num
        );

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch_num, "epoch_num")?;

        let position: H256 = H256::from_uint(&position);

        let key = StorageKey::new_storage_key(
            &address.hex_address,
            position.as_ref(),
        )
        .with_native_space();

        Ok(match state_db.get::<StorageValue>(key)? {
            Some(entry) => Some(H256::from_uint(&entry.value).into()),
            None => None,
        })
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> RpcResult<H256> {
        // if let Call(address) = &tx.transaction.action {
        //     if !address.is_valid_address() {
        //         bail!(invalid_params("tx", "Sending transactions to invalid
        // address. The first four bits must be 0x0 (built-in/reserved), 0x1
        // (user-account), or 0x8 (contract)."));     }
        // }
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

    fn prepare_transaction(
        &self, mut tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<TransactionWithSignature> {
        let consensus_graph = self.consensus_graph();
        tx.check_rpc_address_network(
            "tx",
            self.sync.network.get_network_type(),
        )?;

        if tx.nonce.is_none() {
            // The address can come from invalid address space. TODO: implement
            // the check.

            let nonce = consensus_graph.next_nonce(
                Address::from(tx.from.clone()).with_native_space(),
                BlockHashOrEpochNumber::EpochNumber(EpochNumber::LatestState)
                    .into_primitive(),
                // For an invalid_params error, the name of the params should
                // be provided. the "next_nonce" function may return
                // invalid_params error on an unsupported epoch_number.
                "internal EpochNumber::LatestState",
            )?;
            tx.nonce.replace(nonce.into());
            debug!("after loading nonce in latest state, tx = {:?}", tx);
        }

        let epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        tx.sign_with(
            epoch_height,
            chain_id.in_native_space(),
            password,
            self.accounts.clone(),
        )
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
        Ok(format!("0x{}", raw_tx.to_hex::<String>()))
    }

    fn storage_root(
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
            .get_original_storage_root(
                &address.hex_address.with_native_space(),
            )?;

        Ok(Some(root))
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

        if let Some((
            tx,
            TransactionInfo {
                tx_index,
                maybe_executed_extra_info,
            },
        )) = self.consensus.get_transaction_info_by_hash(&hash)
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
                        .get_data_manager()
                        .get_executed_state_root(&tx_index.block_hash);

                    PackedOrExecuted::Executed(RpcReceipt::new(
                        tx.clone(),
                        receipt,
                        tx_index,
                        prior_gas_used,
                        epoch_number,
                        block_number,
                        maybe_state_root,
                        tx_exec_error_msg,
                        *self.sync.network.get_network_type(),
                    )?)
                }
            };
            let rpc_tx = RpcTransaction::from_signed(
                &tx,
                Some(packed_or_executed),
                *self.sync.network.get_network_type(),
            )?;

            return Ok(Some(rpc_tx));
        }

        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            if tx.space() == Space::Ethereum {
                return Ok(None);
            }

            let rpc_tx = RpcTransaction::from_signed(
                &tx,
                None,
                *self.sync.network.get_network_type(),
            )?;
            return Ok(Some(rpc_tx));
        }

        Ok(None)
    }

    fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> RpcResult<Option<BlockExecInfo>> {
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
    ) -> RpcResult<Option<RpcReceipt>> {
        let id = tx_index.real_index;

        if id >= exec_info.block.transactions.len()
            || id >= exec_info.block_receipts.receipts.len()
            || id >= exec_info.block_receipts.tx_execution_error_messages.len()
        {
            bail!("Inconsistent state");
        }

        let tx = &exec_info.block.transactions[id];

        if tx.space() == Space::Ethereum || tx_index.is_phantom {
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
            exec_info.maybe_state_root.clone(),
            tx_exec_error_msg,
            *self.sync.network.get_network_type(),
        )?;

        Ok(Some(receipt))
    }

    fn prepare_receipt(&self, tx_hash: H256) -> RpcResult<Option<RpcReceipt>> {
        // Note: `transaction_index_by_hash` might return outdated results if
        // there was a pivot chain reorg but the tx was not re-executed yet. In
        // this case, `block_execution_results_by_hash` will detect that the
        // execution results do not match the current pivot view and return
        // None. If the tx was re-executed in another block on the new pivot
        // chain, `transaction_index_by_hash` will return the updated result.
        let tx_index =
            match self.consensus.get_data_manager().transaction_index_by_hash(
                &tx_hash, false, /* update_cache */
            ) {
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

        let receipt = self.construct_rpc_receipt(tx_index, &exec_info)?;
        if let Some(r) = &receipt {
            // A skipped transaction is not available to clients if accessed by
            // its hash.
            if r.outcome_status
                == TransactionOutcome::Skipped.in_space(Space::Native).into()
            {
                return Ok(None);
            }
        }
        Ok(receipt)
    }

    fn prepare_block_receipts(
        &self, block_hash: H256, pivot_assumption: H256,
    ) -> RpcResult<Option<Vec<RpcReceipt>>> {
        let exec_info = match self.get_block_execution_info(&block_hash)? {
            None => return Ok(None), // not executed
            Some(res) => res,
        };

        // pivot chain reorg
        if pivot_assumption != exec_info.pivot_hash {
            bail!(pivot_assumption_failed(
                pivot_assumption,
                exec_info.pivot_hash
            ));
        }

        let mut rpc_receipts = vec![];

        let iter = exec_info
            .block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| tx.space() == Space::Native)
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
            )? {
                rpc_receipts.push(receipt);
            }
        }

        Ok(Some(rpc_receipts))
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
        adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>,
    ) -> RpcResult<H256>
    {
        info!(
            "RPC Request: generate_fixed_block({:?}, {:?}, {:?}, {:?}, {:?})",
            parent_hash, referee, num_txs, difficulty, pos_reference,
        );
        Ok(self.block_gen.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty.unwrap_or(0),
            adaptive,
            pos_reference,
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
                        self.consensus.best_chain_id().in_native_space(),
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
            let public = match tx.recover_public() {
                Ok(public) => public,
                Err(e) => {
                    bail!(invalid_params(
                        &format!("raw_txs, tx {:?}", tx),
                        format!("Recover public error: {:?}", e),
                    ));
                }
            };

            let mut signed_tx = SignedTransaction::new(public, tx);

            // set fake data for latency tests
            match signed_tx.transaction.transaction.unsigned {
                Transaction::Native(ref mut unsigned) if tx_data_len > 0 => {
                    unsigned.data = vec![0; tx_data_len];
                }
                Transaction::Ethereum(ref mut unsigned) if tx_data_len > 0 => {
                    unsigned.data = vec![0; tx_data_len];
                }
                _ => {}
            };

            transactions.push(Arc::new(signed_tx));
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

    fn get_logs(&self, filter: CfxRpcLogFilter) -> RpcResult<Vec<RpcLog>> {
        // all addresses specified should be for the correct network
        if let Some(addresses) = &filter.address {
            for address in addresses.iter() {
                invalid_params_check(
                    "filter.address",
                    check_rpc_address_network(
                        Some(address.network),
                        self.sync.network.get_network_type(),
                    ),
                )?;
            }
        }

        let consensus_graph = self.consensus_graph();

        info!("RPC Request: cfx_getLogs({:?})", filter);
        let filter: LogFilter = filter.into_primitive()?;

        let logs = consensus_graph
            .logs(filter)?
            .iter()
            .cloned()
            .map(|l| {
                RpcLog::try_from_localized(
                    l,
                    *self.sync.network.get_network_type(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // If the results does not fit into `max_limit`, report an error
        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if logs.len() > max_limit {
                bail!(invalid_params("filter", format!("This query results in too many logs, max limitation is {}, please filter results by a smaller epoch/block range", max_limit)));
            }
        }

        Ok(logs)
    }

    fn get_block_reward_info(
        &self, epoch: EpochNumber,
    ) -> RpcResult<Vec<RpcRewardInfo>> {
        info!(
            "RPC Request: cfx_getBlockRewardInfo epoch_number={:?}",
            epoch
        );
        let epoch_height: U64 = self
            .consensus_graph()
            .get_height_from_epoch_number(epoch.clone().into_primitive())?
            .into();
        let (epoch_later_number, overflow) =
            epoch_height.overflowing_add(REWARD_EPOCH_COUNT.into());
        if overflow {
            bail!(invalid_params("epoch", "Epoch number overflows!"));
        }
        let epoch_later = match self.consensus.get_hash_from_epoch_number(
            EpochNumber::Num(epoch_later_number).into_primitive(),
        ) {
            Ok(hash) => hash,
            Err(e) => {
                debug!("get_block_reward_info: get_hash_from_epoch_number returns error: {}", e);
                bail!(invalid_params("epoch", "Reward not calculated yet!"))
            }
        };

        let blocks = self.consensus.get_block_hashes_by_epoch(epoch.into())?;

        let mut ret = Vec::new();
        for b in blocks {
            if let Some(reward_result) = self
                .consensus
                .get_data_manager()
                .block_reward_result_by_hash_with_epoch(
                    &b,
                    &epoch_later,
                    false, // update_pivot_assumption
                    true,  // update_cache
                )
            {
                if let Some(block_header) =
                    self.consensus.get_data_manager().block_header_by_hash(&b)
                {
                    let author = RpcAddress::try_from_h160(
                        *block_header.author(),
                        *self.sync.network.get_network_type(),
                    )?;

                    ret.push(RpcRewardInfo::new(b, author, reward_result));
                }
            }
        }
        Ok(ret)
    }

    fn call(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        match self.exec_transaction(request, epoch)? {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                expected,
                got,
            )) => bail!(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"nonce is too old expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::InvalidRecipientAddress(recipient),
            ) => bail!(call_execution_error(
                "Transaction can not be executed".into(),
                format! {"invalid recipient address {:?}", recipient}
            )),
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(call_execution_error(
                    "Transaction can not be executed".into(),
                    format! {"{:?}", e}
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(vm::Error::Reverted),
                executed,
            ) => bail!(call_execution_error(
                "Transaction reverted".into(),
                format!("0x{}", executed.output.to_hex::<String>())
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(e, _) => {
                bail!(call_execution_error(
                    "Transaction execution failed".into(),
                    format! {"{:?}", e}
                ))
            }
            ExecutionOutcome::Finished(executed) => Ok(executed.output.into()),
        }
    }

    fn estimate_gas_and_collateral(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        info!(
            "RPC Request: cfx_estimateGasAndCollateral request={:?}, epoch={:?}",request,epoch
        );
        let executed = match self.exec_transaction(request, epoch)? {
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
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(call_execution_error(
                    "Can not estimate: transaction can not be executed".into(),
                    format! {"{:?}", e}
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(vm::Error::Reverted),
                executed,
            ) => {
                let network_type = *self.sync.network.get_network_type();

                // When a revert exception happens, there is usually an error in
                // the sub-calls. So we return the trace
                // information for debugging contract.
                let errors = ErrorUnwind::from_traces(executed.trace)
                    .errors
                    .iter()
                    .map(|(addr, error)| {
                        let cip37_addr = RpcAddress::try_from_h160(
                            addr.clone(),
                            network_type,
                        )
                        .unwrap()
                        .base32_address;
                        format!("{}: {}", cip37_addr, error)
                    })
                    .collect::<Vec<String>>();

                // Decode revert error
                let revert_error = revert_reason_decode(&executed.output);
                let revert_error = if !revert_error.is_empty() {
                    format!(": {}.", revert_error)
                } else {
                    format!(".")
                };

                // Try to fetch the innermost error.
                let innermost_error = if errors.len() > 0 {
                    format!(" Innermost error is at {}.", errors[0])
                } else {
                    String::default()
                };

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
            ExecutionOutcome::Finished(executed) => executed,
        };
        let storage_collateralized =
            U64::from(executed.estimated_storage_limit);
        let estimated_gas_limit =
            executed.estimated_gas_limit.unwrap_or(U256::zero());
        let response = EstimateGasAndCollateralResponse {
            // We multiply the gas_used for 2 reasons:
            // 1. In each EVM call, the gas passed is at most 63/64 of the
            // remaining gas, so the gas_limit should be multiplied a factor so
            // that the gas passed into the sub-call is sufficient. The 4 / 3
            // factor is sufficient for 18 level of calls.
            // 2. In Conflux, we recommend setting the gas_limit to (gas_used *
            // 4) / 3, because the extra gas will be refunded up to
            // 1/4 of the gas limit.
            gas_limit: executed.estimated_gas_limit.unwrap(),
            gas_used: estimated_gas_limit,
            storage_collateralized,
        };
        Ok(response)
    }

    fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> RpcResult<CheckBalanceAgainstTransactionResponse>
    {
        self.check_address_network(account_addr.network)?;
        self.check_address_network(contract_addr.network)?;

        let epoch: primitives::EpochNumber =
            epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_checkBalanceAgainstTransaction account_addr={:?} contract_addr={:?} gas_limit={:?} gas_price={:?} storage_limit={:?} epoch={:?}",
            account_addr, contract_addr, gas_limit, gas_price, storage_limit, epoch
        );

        let account_addr = account_addr.hex_address.with_native_space();
        let contract_addr = contract_addr.hex_address.with_native_space();

        if storage_limit > U256::from(std::u64::MAX) {
            bail!(JsonRpcError::invalid_params(format!("storage_limit has to be within the range of u64 but {} supplied!", storage_limit)));
        }

        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch, "epoch")?;

        let user_account = state_db.get_account(&account_addr)?;
        let contract_account = state_db.get_account(&contract_addr)?;
        let state = State::new(state_db)?;
        let is_sponsored = state.check_commission_privilege(
            &contract_addr.address,
            &account_addr.address,
        )?;

        Ok(common::check_balance_against_transaction(
            user_account,
            contract_account,
            is_sponsored,
            gas_limit,
            gas_price,
            storage_limit,
        ))
    }

    fn exec_transaction(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<ExecutionOutcome> {
        let rpc_request_network = invalid_params_check(
            "request",
            rpc_call_request_network(
                request.from.as_ref(),
                request.to.as_ref(),
            ),
        )?;
        invalid_params_check(
            "request",
            check_rpc_address_network(
                rpc_request_network,
                self.sync.network.get_network_type(),
            ),
        )?;

        let consensus_graph = self.consensus_graph();
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);

        let estimate_request = EstimateRequest {
            has_sender: request.from.is_some(),
            has_gas_limit: request.gas.is_some(),
            has_gas_price: request.gas_price.is_some(),
            has_nonce: request.nonce.is_some(),
            has_storage_limit: request.storage_limit.is_some(),
        };

        let best_epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        let signed_tx =
            sign_call(best_epoch_height, chain_id.in_native_space(), request)?;
        trace!("call tx {:?}", signed_tx);

        consensus_graph.call_virtual(&signed_tx, epoch.into(), estimate_request)
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

    pub fn get_supply_info(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcResult<TokenSupplyInfo> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();
        let state = State::new(
            self.consensus
                .get_state_db_by_epoch_number(epoch, "epoch")?,
        )?;
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

    pub fn get_vote_params(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcResult<VoteParamsInfo> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();
        let state_db = self
            .consensus
            .get_state_db_by_epoch_number(epoch, "epoch_num")?;
        let interest_rate =
            state_db.get_annual_interest_rate()? / U256::from(BLOCKS_PER_YEAR);
        let pow_base_reward =
            state_db.get_pow_base_reward()?.unwrap_or_default();

        Ok(VoteParamsInfo {
            pow_base_reward,
            interest_rate,
        })
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

    // estimate response size, return error if it is too large
    // note: this is a potentially expensive check
    fn check_response_size<T: Serialize>(&self, response: &T) -> RpcResult<()> {
        // account for the enclosing JSON object
        // {"jsonrpc":"2.0","id":1,"result": ... }
        // note: this is a rough estimation
        let max_size = self.config.max_payload_bytes - 50;

        let payload_size = serde_json::to_vec(&response)
            .map_err(|_e| "Unexpected serialization error")?
            .len();

        if payload_size > max_size {
            // TODO(thegaram): should we define a new error type?
            bail!(invalid_params(
                "epoch",
                format!(
                    "Oversized payload: size = {}, max = {}",
                    payload_size, max_size
                )
            ));
        }

        Ok(())
    }

    fn get_block_epoch_number(&self, h: &H256) -> Option<u64> {
        // try to get from memory
        if let Some(e) = self.consensus.get_block_epoch_number(h) {
            return Some(e);
        }

        // try to get from db
        self.consensus.get_data_manager().block_epoch_number(h)
    }

    fn epoch_receipts(
        &self, epoch: BlockHashOrEpochNumber,
    ) -> RpcResult<Option<Vec<Vec<RpcReceipt>>>> {
        info!("RPC Request: cfx_getEpochReceipts({:?})", epoch);

        let hashes = match epoch {
            BlockHashOrEpochNumber::EpochNumber(e) => {
                self.consensus.get_block_hashes_by_epoch(e.into())?
            }
            BlockHashOrEpochNumber::BlockHash(h) => {
                if self
                    .consensus
                    .get_data_manager()
                    .block_header_by_hash(&h)
                    .is_none()
                {
                    bail!(invalid_params("block_hash", "block not found"));
                }

                let e = match self.get_block_epoch_number(&h) {
                    Some(e) => e,
                    None => return Ok(None), // not executed
                };

                let hashes = self.consensus.get_block_hashes_by_epoch(
                    primitives::EpochNumber::Number(e),
                )?;

                // if the provided hash is not the pivot hash, abort
                let pivot_hash = *hashes.last().ok_or("Inconsistent state")?;

                if h != pivot_hash {
                    bail!(pivot_assumption_failed(h, pivot_hash));
                }

                hashes
            }
        };

        let pivot_hash = *hashes.last().ok_or("Inconsistent state")?;
        let mut epoch_receipts = vec![];

        for h in hashes {
            epoch_receipts.push(
                match self.prepare_block_receipts(h, pivot_hash)? {
                    None => return Ok(None), // not executed
                    Some(rs) => rs,
                },
            );
        }

        // TODO(thegaram): we should only do this on WS, not on HTTP
        // how to treat these differently?
        self.check_response_size(&epoch_receipts)?;

        Ok(Some(epoch_receipts))
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
                &self, epoch_num: EpochNumber, include_txs: bool) -> BoxFuture<Option<RpcBlock>>;
            fn block_by_hash_with_pivot_assumption(
                &self, block_hash: H256, pivot_hash: H256, epoch_number: U64)
                -> BoxFuture<RpcBlock>;
            fn block_by_hash(&self, hash: H256, include_txs: bool)
                -> BoxFuture<Option<RpcBlock>>;
            fn block_by_block_number(&self, block_number: U64, include_txs: bool) -> BoxFuture<Option<RpcBlock>>;
            fn confirmation_risk_by_hash(&self, block_hash: H256) -> JsonRpcResult<Option<U256>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<U256>;
            fn gas_price(&self) -> BoxFuture<U256>;
            fn next_nonce(&self, address: RpcAddress, num: Option<BlockHashOrEpochNumber>)
                -> BoxFuture<U256>;
            fn get_status(&self) -> JsonRpcResult<RpcStatus>;
            fn get_client_version(&self) -> JsonRpcResult<String>;
            fn account_pending_info(&self, addr: RpcAddress) -> BoxFuture<Option<AccountPendingInfo>>;
            fn account_pending_transactions(&self, address: RpcAddress, maybe_start_nonce: Option<U256>, maybe_limit: Option<U64>) -> BoxFuture<AccountPendingTransactions>;
            fn get_pos_reward_by_epoch(&self, epoch: EpochNumber) -> JsonRpcResult<Option<PoSEpochReward>>;
        }

        to self.rpc_impl {
            fn code(&self, addr: RpcAddress, epoch_number: Option<EpochNumber>) -> BoxFuture<Bytes>;
            fn account(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn pos_economics(&self, num: Option<EpochNumber>) -> BoxFuture<PoSEconomics>;
            fn admin(&self, address: RpcAddress, num: Option<EpochNumber>)
                -> BoxFuture<Option<RpcAddress>>;
            fn sponsor_info(&self, address: RpcAddress, num: Option<EpochNumber>)
                -> BoxFuture<SponsorInfo>;
            fn balance(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn staking_balance(&self, address: RpcAddress, num: Option<EpochNumber>)
                -> BoxFuture<U256>;
            fn deposit_list(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<Vec<DepositInfo>>;
            fn vote_list(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<Vec<VoteStakeInfo>>;
            fn collateral_for_storage(&self, address: RpcAddress, num: Option<EpochNumber>)
                -> BoxFuture<U256>;
            fn call(&self, request: CallRequest, epoch: Option<EpochNumber>)
                -> JsonRpcResult<Bytes>;
            fn estimate_gas_and_collateral(
                &self, request: CallRequest, epoch_number: Option<EpochNumber>)
                -> JsonRpcResult<EstimateGasAndCollateralResponse>;
            fn check_balance_against_transaction(
                &self, account_addr: RpcAddress, contract_addr: RpcAddress, gas_limit: U256, gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>,
            ) -> BoxFuture<CheckBalanceAgainstTransactionResponse>;
            fn get_logs(&self, filter: CfxRpcLogFilter) -> BoxFuture<Vec<RpcLog>>;
            fn get_block_reward_info(&self, num: EpochNumber) -> JsonRpcResult<Vec<RpcRewardInfo>>;
            fn send_raw_transaction(&self, raw: Bytes) -> JsonRpcResult<H256>;
            fn storage_at(&self, addr: RpcAddress, pos: U256, epoch_number: Option<EpochNumber>)
                -> BoxFuture<Option<H256>>;
            fn transaction_by_hash(&self, hash: H256) -> BoxFuture<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: H256) -> BoxFuture<Option<RpcReceipt>>;
            fn storage_root(&self, address: RpcAddress, epoch_num: Option<EpochNumber>) -> BoxFuture<Option<StorageRoot>>;
            fn get_supply_info(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<TokenSupplyInfo>;
            fn get_vote_params(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<VoteParamsInfo>;
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
            fn pos_register(&self, voting_power: U64) -> JsonRpcResult<(Bytes, AccountAddress)>;
            fn pos_update_voting_power(
                &self, pos_account: AccountAddress, increased_voting_power: U64,
            ) -> JsonRpcResult<()>;
            fn pos_stop_election(&self) -> JsonRpcResult<Option<u64>>;
            fn pos_start_voting(&self, initialize: bool) -> JsonRpcResult<()>;
            fn pos_stop_voting(&self) -> JsonRpcResult<()>;
            fn pos_voting_status(&self) -> JsonRpcResult<bool>;
            fn pos_start(&self) -> JsonRpcResult<()>;
            fn pos_force_vote_proposal(&self, block_id: H256) -> JsonRpcResult<()>;
            fn pos_force_propose(&self, round: U64, parent_block_id: H256, payload: Vec<TransactionPayload>) -> JsonRpcResult<()>;
            fn pos_trigger_timeout(&self, timeout_type: String) -> JsonRpcResult<()>;
            fn pos_force_sign_pivot_decision(&self, block_hash: H256, height: U64) -> JsonRpcResult<()>;
            fn pos_get_chosen_proposal(&self) -> JsonRpcResult<Option<PosBlock>>;
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
                &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>)
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
            fn txpool_content(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_get_account_transactions(&self, address: RpcAddress) -> JsonRpcResult<Vec<RpcTransaction>>;
            fn txpool_clear(&self) -> JsonRpcResult<()>;
            fn net_node(&self, id: NodeId) -> JsonRpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>)
                -> JsonRpcResult<bool>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> JsonRpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> JsonRpcResult<throttling::Service>;
            fn accounts(&self) -> JsonRpcResult<Vec<RpcAddress>>;
            fn new_account(&self, password: String) -> JsonRpcResult<RpcAddress>;
            fn unlock_account(
                &self, address: RpcAddress, password: String, duration: Option<U128>)
                -> JsonRpcResult<bool>;
            fn lock_account(&self, address: RpcAddress) -> JsonRpcResult<bool>;
            fn sign(&self, data: Bytes, address: RpcAddress, password: Option<String>)
                -> JsonRpcResult<H520>;

        }

        to self.rpc_impl {
            fn current_sync_phase(&self) -> JsonRpcResult<String>;
            fn consensus_graph_state(&self) -> JsonRpcResult<ConsensusGraphStates>;
            fn epoch_receipts(&self, epoch: BlockHashOrEpochNumber) -> JsonRpcResult<Option<Vec<Vec<RpcReceipt>>>>;
            fn sync_graph_state(&self) -> JsonRpcResult<SyncGraphStates>;
            fn send_transaction(
                &self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<H256>;
            fn sign_transaction(&self, tx: SendTxRequest, password: Option<String>) -> JsonRpcResult<String>;
        }
    }
}
