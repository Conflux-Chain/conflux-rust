// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    helpers::errors::execution_error,
    impls::common::RpcImpl as CommonImpl,
    traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
    types::{
        sign_call, Account as RpcAccount, BlameInfo, Block as RpcBlock,
        BlockHashOrEpochNumber, Bytes, CallRequest, ConsensusGraphStates,
        EpochNumber, EstimateGasAndCollateralResponse, Filter as RpcFilter,
        Log as RpcLog, Receipt as RpcReceipt, SendTxRequest,
        SponsorInfo as RpcSponsorInfo, Status as RpcStatus, SyncGraphStates,
        Transaction as RpcTransaction, H160 as RpcH160, H256 as RpcH256,
        H520 as RpcH520, U128 as RpcU128, U256 as RpcU256, U64 as RpcU64,
    },
};
use blockgen::BlockGenerator;
use cfx_types::{H160, H256, U256};
use cfxcore::{
    block_data_manager::BlockExecutionResultWithEpoch,
    block_parameters::MAX_BLOCK_SIZE_IN_BYTES, executive::Executed,
    state_exposer::STATE_EXPOSER, test_context::*, ConsensusGraph,
    ConsensusGraphTrait, PeerInfo, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use delegate::delegate;
use jsonrpc_core::{BoxFuture, Error as RpcError, Result as RpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use parking_lot::Mutex;
use primitives::{
    filter::Filter, transaction::Action::Call, SignedTransaction,
    TransactionWithSignature,
};
use rlp::Rlp;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
use txgen::{DirectTransactionGenerator, TransactionGenerator};

#[derive(Default)]
pub struct RpcImplConfiguration {
    pub get_logs_filter_max_limit: Option<usize>,
}

pub struct RpcImpl {
    config: RpcImplConfiguration,
    pub consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    block_gen: Arc<BlockGenerator>,
    tx_pool: SharedTransactionPool,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
}

impl RpcImpl {
    pub fn new(
        consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        block_gen: Arc<BlockGenerator>, tx_pool: SharedTransactionPool,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
        config: RpcImplConfiguration,
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
        }
    }

    fn code(
        &self, addr: RpcH160, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let epoch_number = epoch_number.unwrap_or(EpochNumber::LatestState);
        let address: H160 = addr.into();
        info!(
            "RPC Request: cfx_getCode address={:?} epoch_num={:?}",
            address, epoch_number
        );
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_code(address, epoch_number.into())
            .map(Bytes::new)
            .map_err(RpcError::invalid_params)
    }

    fn balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch_num={:?}",
            address, num
        );

        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_balance(address, num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    fn admin(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcH160> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch_num={:?}",
            address, num
        );

        let cg = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        cg.get_admin(address, num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    fn sponsor_info(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcSponsorInfo> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch_num={:?}",
            address, num
        );

        let cg = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        cg.get_sponsor_info(address, num.into())
            .map(|x| RpcSponsorInfo::new(x))
            .map_err(RpcError::invalid_params)
    }

    fn staking_balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch_num={:?}",
            address, num
        );

        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_staking_balance(address, num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    fn collateral_for_storage(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(EpochNumber::LatestState);
        let address: H160 = address.into();
        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch_num={:?}",
            address, num
        );

        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_collateral_for_storage(address, num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    /// Return account related states of the given account
    fn account(
        &self, address: RpcH160, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        let address: H160 = address.into();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getAccount address={:?} epoch_num={:?}",
            address, epoch_num
        );
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_account(address, epoch_num.into())
            .map(|acc| RpcAccount::new(acc))
            .map_err(RpcError::invalid_params)
    }

    /// Returns interest rate of the given epoch
    fn interest_rate(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_annual_interest_rate(epoch_num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    /// Returns accumulate interest rate of the given epoch
    fn accumulate_interest_rate(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_accumulate_interest_rate(epoch_num.into())
            .map(|x| x.into())
            .map_err(RpcError::invalid_params)
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);

        let tx = Rlp::new(&raw.into_vec()).as_val().map_err(|err| {
            RpcError::invalid_params(format!("Error: {:?}", err))
        })?;

        self.send_transaction_with_signature(tx)
    }

    fn storage_at(
        &self, address: RpcH160, position: RpcH256,
        epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcH256>>
    {
        let address: H160 = address.into();
        let position: H256 = position.into();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            address, position, epoch_num
        );

        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_storage(address, position, epoch_num.into())
            .map(|x| x.map(Into::into))
            .map_err(RpcError::invalid_params)
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> RpcResult<RpcH256> {
        if let Call(H160(r)) = &tx.transaction.action {
            let type_bits = r[0] & 0xf0;
            if !(type_bits == 0x0 || type_bits == 0x10 || type_bits == 0x80) {
                return Err(RpcError::invalid_params("Sending transactions to invalid address. The first four bits must be 0x0 (built-in/reserved), 0x1 (user-account), or 0x8 (contract)."));
            }
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
            Err(RpcError::invalid_params(String::from("tx already exist")))
        } else if signed_trans.is_empty() {
            let tx_err = failed_trans.iter().next().expect("Not empty").1;
            Err(RpcError::invalid_params(tx_err))
        } else {
            let tx_hash = signed_trans[0].hash();
            self.sync.append_received_transactions(signed_trans);
            Ok(tx_hash.into())
        }
    }

    fn prepare_transaction(
        &self, mut tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<TransactionWithSignature> {
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

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
                    RpcError::invalid_params(format!(
                        "failed to send transaction: {:?}",
                        e
                    ))
                })?;
            tx.nonce.replace(nonce.into());
            debug!("after loading nonce in latest state, tx = {:?}", tx);
        }

        let epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        let tx =
            tx.sign_with(epoch_height, chain_id, password)
                .map_err(|e| {
                    RpcError::invalid_params(format!(
                        "failed to send transaction: {:?}",
                        e
                    ))
                })?;

        Ok(tx)
    }

    fn send_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<RpcH256> {
        info!("RPC Request: send_transaction, tx = {:?}", tx);

        self.prepare_transaction(tx, password)
            .and_then(|tx| self.send_transaction_with_signature(tx))
    }

    fn storage_root(
        &self, address: RpcH160, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcH256>> {
        let address: H160 = address.into();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: storage_hash address={:?} epoch_num={:?}",
            address, epoch_num
        );

        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        consensus_graph
            .get_storage_root(address, epoch_num.into())
            .map(|maybe_hash| maybe_hash.map(Into::into))
            .map_err(RpcError::invalid_params)
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
                let mut rpc_error = RpcError::method_not_found();
                rpc_error.message = "send_usable_genesis_accounts only allowed in test or dev mode with txgen set.".into();
                Err(rpc_error)
            }
            Some(txgen) => {
                txgen.set_genesis_accounts_start_index(account_start_index);
                Ok(Bytes::new("1".into()))
            }
        }
    }

    pub fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> RpcResult<Option<RpcTransaction>> {
        let hash: H256 = hash.into();
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        if let Some(info) = self.consensus.get_transaction_info_by_hash(&hash) {
            let (tx, receipt, tx_index, prior_gas_used) = info;
            let rpc_receipt =
                RpcReceipt::new(tx.clone(), receipt, tx_index, prior_gas_used);
            let rpc_tx = RpcTransaction::from_signed(&tx, Some(rpc_receipt));
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
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        let maybe_results =
            consensus_graph.get_transaction_receipt_and_block_info(&hash);
        let (
            BlockExecutionResultWithEpoch(epoch_hash, execution_result),
            address,
            state_root,
        ) = match maybe_results {
            None => return Ok(None),
            Some(result_tuple) => result_tuple,
        };

        let epoch_block_header = self
            .consensus
            .get_data_manager()
            .block_header_by_hash(&epoch_hash)
            .ok_or(RpcError::internal_error())?;
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
            .ok_or(RpcError::internal_error())?;
        let transaction = block
            .transactions
            .get(address.index)
            .ok_or(RpcError::internal_error())?
            .as_ref()
            .clone();
        let receipt = execution_result
            .receipts
            .get(address.index)
            .ok_or(RpcError::internal_error())?
            .clone();
        let prior_gas_used = if address.index == 0 {
            U256::zero()
        } else {
            let prior_receipt = execution_result
                .receipts
                .get(address.index - 1)
                .ok_or(RpcError::internal_error())?
                .clone();
            prior_receipt.gas_used
        };
        let mut rpc_receipt =
            RpcReceipt::new(transaction, receipt, address, prior_gas_used);
        rpc_receipt.set_epoch_number(Some(epoch_number));
        rpc_receipt.set_state_root(state_root.into());
        Ok(Some(rpc_receipt))
    }

    fn transaction_receipt(
        &self, tx_hash: RpcH256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt({:?})", hash);
        self.prepare_receipt(hash)
    }

    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>> {
        info!("RPC Request: generate({:?})", num_blocks);
        let mut hashes = Vec::new();
        for _i in 0..num_blocks {
            hashes.push(self.block_gen.generate_block(
                0,
                MAX_BLOCK_SIZE_IN_BYTES,
                vec![],
            ));
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
        match self.block_gen.generate_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty.unwrap_or(0),
            adaptive,
        ) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        info!("RPC Request: generate_one_block()");
        let hash =
            self.block_gen
                .generate_block(num_txs, block_size_limit, vec![]);
        Ok(hash)
    }

    fn generate_one_block_with_direct_txgen(
        &self, num_txs: usize, mut block_size_limit: usize,
        num_txs_simple: usize, num_txs_erc20: usize,
    ) -> RpcResult<()>
    {
        info!("RPC Request: generate_one_block_with_direct_txgen()");

        let block_gen = &self.block_gen;
        match self.maybe_direct_txgen.as_ref() {
            None => {
                let mut rpc_error = RpcError::method_not_found();
                rpc_error.message = "generate_one_block_with_direct_txgen only allowed in test or dev mode.".into();
                Err(rpc_error)
            }
            Some(direct_txgen) => {
                let generated_transactions =
                    direct_txgen.lock().generate_transactions(
                        &mut block_size_limit,
                        num_txs_simple,
                        num_txs_erc20,
                    );

                block_gen.generate_block(
                    num_txs,
                    block_size_limit,
                    generated_transactions,
                );
                Ok(())
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

        match self.block_gen.generate_custom_block_with_parent(
            parent_hash,
            referee,
            transactions,
            adaptive.unwrap_or(false),
        ) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: u64,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256>
    {
        let transactions = self.decode_raw_txs(raw, 0)?;
        match self.block_gen.generate_block_with_nonce_and_timestamp(
            parent,
            referees,
            transactions,
            nonce,
            timestamp,
            adaptive,
        ) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    fn decode_raw_txs(
        &self, raw_txs: Bytes, tx_data_len: usize,
    ) -> RpcResult<Vec<Arc<SignedTransaction>>> {
        let txs: Vec<TransactionWithSignature> =
            Rlp::new(&raw_txs.into_vec()).as_list().map_err(|err| {
                RpcError::invalid_params(format!("Decode error: {:?}", err))
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
                    return Err(RpcError::invalid_params(format!(
                        "Recover public error: {:?}",
                        e
                    )));
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
            blame_info.blame,
            blame_info.deferred_state_root.map(|x| x.into()),
            blame_info.deferred_receipts_root.map(|x| x.into()),
            blame_info.deferred_logs_bloom_hash.map(|x| x.into()),
        ))
    }

    fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>> {
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");

        info!("RPC Request: cfx_getLogs({:?})", filter);
        let mut filter: Filter = filter.into();

        // If max_limit is set, the value in `filter` will be modified to
        // satisfy this limitation to avoid loading too many blocks
        // TODO Should the response indicates that the filter is modified?
        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if filter.limit.is_none() || filter.limit.unwrap() > max_limit {
                filter.limit = Some(max_limit);
            }
        }

        consensus_graph
            .logs(filter)
            .map_err(|e| format!("{}", e))
            .map_err(RpcError::invalid_params)
            .map(|logs| logs.iter().cloned().map(RpcLog::from).collect())
    }

    fn call(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        let success_executed = self.exec_transaction(request, epoch)?;
        Ok(Bytes::new(success_executed.output))
    }

    fn estimate_gas_and_collateral(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        let caller = request.from.unwrap_or_default();
        let success_executed = self.exec_transaction(request, epoch)?;
        let mut storage_collateralized = 0;
        for storage_change in &success_executed.storage_collateralized {
            if storage_change.address == caller {
                storage_collateralized = storage_change.amount;
            }
        }
        let response = EstimateGasAndCollateralResponse {
            gas_used: success_executed.gas_used.into(),
            storage_collateralized: storage_collateralized.into(),
        };
        Ok(response)
    }

    fn exec_transaction(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<Executed> {
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");
        let epoch = epoch.unwrap_or(EpochNumber::LatestState);

        let best_epoch_height = consensus_graph.best_epoch_number();
        let chain_id = consensus_graph.best_chain_id();
        let signed_tx = sign_call(best_epoch_height, chain_id, request)
            .map_err(|err| {
                RpcError::invalid_params(format!("Sign tx error: {:?}", err))
            })?;
        trace!("call tx {:?}", signed_tx);
        let executed = consensus_graph
            .call_virtual(&signed_tx, epoch.into())
            .map_err(RpcError::invalid_params)?;
        match executed.exception {
            None => Ok(executed),
            Some(exception) => {
                Err(execution_error(exception.to_string(), executed.output))
            }
        }
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        Ok(self.sync.current_sync_phase().name().into())
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
        let consensus_graph = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed");
        let status = consensus_graph
            .data_man
            .local_block_info_from_db(&block_hash)
            .ok_or(RpcError::invalid_params("No block status"))?
            .get_status();
        let state_valid = consensus_graph
            .inner
            .read()
            .block_node(&block_hash)
            .ok_or(RpcError::invalid_params("No block in consensus"))?
            .data
            .state_valid
            .ok_or(RpcError::invalid_params("No state_valid"))?;
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

// Use the #[into] attribute to convert from RpcResult to BoxFuture
// automatically.
use crate::common::delegate_convert;
impl Cfx for CfxHandler {
    delegate! {
        to self.common {
            fn best_block_hash(&self) -> RpcResult<RpcH256>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> RpcResult<RpcBlock>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64) -> RpcResult<RpcBlock>;
            fn block_by_hash(&self, hash: RpcH256, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn gas_price(&self) -> RpcResult<RpcU256>;
            fn next_nonce(&self, address: RpcH160, num: Option<BlockHashOrEpochNumber>) -> RpcResult<RpcU256>;
        }

        to self.rpc_impl {
            #[into]
            fn code(&self, addr: RpcH160, epoch_number: Option<EpochNumber>) -> BoxFuture<Bytes>;
            #[into]
            fn account(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            #[into]
            fn admin(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcH160>;
            #[into]
            fn sponsor_info(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcSponsorInfo>;
            #[into]
            fn balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            #[into]
            fn staking_balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            #[into]
            fn collateral_for_storage(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            fn call(&self, request: CallRequest, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn estimate_gas_and_collateral(
                &self, request: CallRequest, epoch_number: Option<EpochNumber>)
                -> RpcResult<EstimateGasAndCollateralResponse>;
            #[into]
            fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256>;
            #[into]
            fn storage_at(&self, addr: RpcH160, pos: RpcH256, epoch_number: Option<EpochNumber>)
                -> BoxFuture<Option<RpcH256>>;
            #[into]
            fn transaction_by_hash(&self, hash: RpcH256) -> BoxFuture<Option<RpcTransaction>>;
            #[into]
            fn transaction_receipt(&self, tx_hash: RpcH256) -> BoxFuture<Option<RpcReceipt>>;
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
            fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;
            fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn chain(&self) -> RpcResult<Vec<RpcBlock>>;
            fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn get_block_count(&self) -> RpcResult<u64>;
            fn get_goodput(&self) -> RpcResult<String>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
            fn save_node_db(&self) -> RpcResult<()>;
        }

        to self.rpc_impl {
            fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
            fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
            fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> RpcResult<H256>;
            fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
            fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
            fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<()>;
            fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
            fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: u64, timestamp: u64, adaptive: bool) -> RpcResult<H256>;
            fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;
            fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)>;
            fn send_usable_genesis_accounts(& self, account_start_index: usize) -> RpcResult<Bytes>;
            fn set_db_crash(&self, crash_probability: f64, crash_exit_code: i32) -> RpcResult<()>;
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
            fn clear_tx_pool(&self) -> RpcResult<()>;
            fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> RpcResult<Option<usize>>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> RpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> RpcResult<throttling::Service>;
            fn tx_inspect(&self, hash: RpcH256) -> RpcResult<BTreeMap<String, String>>;
            fn txpool_content(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;
            fn accounts(&self) -> RpcResult<Vec<RpcH160>>;
            fn new_account(&self, password: String) -> RpcResult<RpcH160>;
            fn unlock_account(&self, address: RpcH160, password: String, duration: Option<RpcU128>) -> RpcResult<bool>;
            fn lock_account(&self, address: RpcH160) -> RpcResult<bool>;
            fn sign(&self, data: Bytes, address: RpcH160, password: Option<String>) -> RpcResult<RpcH520>;
        }

        to self.rpc_impl {
            fn current_sync_phase(&self) -> RpcResult<String>;
            fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
            fn sync_graph_state(&self) -> RpcResult<SyncGraphStates>;
            #[into]
            fn send_transaction(&self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<RpcH256>;
            #[into]
            fn storage_root(&self, address: RpcH160, epoch_num: Option<EpochNumber>) -> BoxFuture<Option<RpcH256>>;
        }
    }
}
