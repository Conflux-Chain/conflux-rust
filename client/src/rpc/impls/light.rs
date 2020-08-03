// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H160, H256, H520, U128, U256, U64};
use cfxcore::{
    rpc_errors::{account_result_to_rpc_result, invalid_params_check},
    LightQueryService, PeerInfo,
};
use cfxcore_accounts::AccountProvider;
use delegate::delegate;
use futures::future::{FutureExt, TryFutureExt};
use futures01;
use jsonrpc_core::{BoxFuture, Error as RpcError, Result as RpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use primitives::{Account, TransactionWithSignature};
use rlp::Encodable;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
// To convert from RpcResult to BoxFuture by delegate! macro automatically.
use crate::{
    common::delegate_convert,
    rpc::{
        error_codes,
        impls::{common::RpcImpl as CommonImpl, RpcImplConfiguration},
        traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
        types::{
            Account as RpcAccount, BlameInfo, Block as RpcBlock,
            BlockHashOrEpochNumber, Bytes, CallRequest,
            CheckBalanceAgainstTransactionResponse, ConsensusGraphStates,
            EpochNumber, EstimateGasAndCollateralResponse, Filter as RpcFilter,
            Log as RpcLog, Receipt as RpcReceipt, RewardInfo as RpcRewardInfo,
            SendTxRequest, SponsorInfo as RpcSponsorInfo, Status as RpcStatus,
            StorageRoot as RpcStorageRoot, SyncGraphStates,
            Transaction as RpcTransaction,
        },
        RpcBoxFuture,
    },
};

pub struct RpcImpl {
    // configuration parameters
    config: RpcImplConfiguration,

    // helper API for retrieving verified information from peers
    light: Arc<LightQueryService>,

    accounts: Arc<AccountProvider>,
}

impl RpcImpl {
    pub fn new(
        config: RpcImplConfiguration, light: Arc<LightQueryService>,
        accounts: Arc<AccountProvider>,
    ) -> Self
    {
        RpcImpl {
            config,
            light,
            accounts,
        }
    }

    fn account(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<RpcAccount> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getAccount address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(RpcAccount::new(account.unwrap_or(
                account_result_to_rpc_result(
                    "address",
                    Account::new_empty_with_balance(
                        &address,
                        &U256::zero(), /* balance */
                        &U256::zero(), /* nonce */
                    ),
                )?,
            )))
        };

        Box::new(fut.boxed().compat())
    }

    fn balance(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(account
                .map(|account| account.balance.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    fn admin(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<Option<H160>> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(account.map(|account| account.admin.into()))
        };

        Box::new(fut.boxed().compat())
    }

    fn sponsor_info(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<RpcSponsorInfo> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(RpcSponsorInfo::new(
                account.map_or(Default::default(), |acc| acc.sponsor_info),
            ))
        };

        Box::new(fut.boxed().compat())
    }

    fn staking_balance(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(account
                .map(|account| account.staking_balance.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    fn collateral_for_storage(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(account
                .map(|account| account.collateral_for_storage.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    #[allow(unused_variables)]
    fn call(
        &self, request: CallRequest, epoch: Option<EpochNumber>,
    ) -> RpcResult<Bytes> {
        // TODO(thegaram)
        Err(error_codes::unimplemented(None))
    }

    #[allow(unused_variables)]
    fn sign_transaction(
        &self, tx: SendTxRequest, password: Option<String>,
    ) -> RpcResult<String> {
        // TODO
        Err(error_codes::unimplemented(None))
    }

    fn code(
        &self, address: H160, epoch_num: Option<EpochNumber>,
    ) -> RpcBoxFuture<Bytes> {
        let address: H160 = address.into();
        let epoch = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCode address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            // FIMXE:
            //  We should get rid of the invalid_params_check when the
            //  error conversion is done within the light service methods.
            //  Same for all other usages here in this file.
            Ok(Bytes::new(
                invalid_params_check(
                    "address",
                    light.get_code(epoch, address).await,
                )?
                .unwrap_or_default(),
            ))
        };

        Box::new(fut.boxed().compat())
    }

    #[allow(unused_variables)]
    fn estimate_gas_and_collateral(
        &self, request: CallRequest, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        // TODO(thegaram)
        Err(error_codes::unimplemented(None))
    }

    fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>> {
        info!("RPC Request: cfx_getLogs filter={:?}", filter);

        let mut filter = match filter.into_primitive() {
            Ok(filter) => filter,
            Err(e) => return Box::new(futures01::future::err(e)),
        };

        // If max_limit is set, the value in `filter` will be modified to
        // satisfy this limitation to avoid loading too many blocks
        // TODO Should the response indicate that the filter is modified?
        if let Some(max_limit) = self.config.get_logs_filter_max_limit {
            if filter.limit.is_none() || filter.limit.unwrap() > max_limit {
                filter.limit = Some(max_limit);
            }
        }

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let logs = light
                .get_logs(filter)
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            Ok(logs.into_iter().map(RpcLog::from).collect())
        };

        Box::new(fut.boxed().compat())
    }

    fn send_tx_helper(
        light: Arc<LightQueryService>, raw: Bytes,
    ) -> RpcResult<H256> {
        let raw: Vec<u8> = raw.into_vec();

        // decode tx so that we have its hash
        // this way we also avoid spamming peers with invalid txs
        let tx: TransactionWithSignature = rlp::decode(&raw.clone())
            .map_err(|e| format!("Failed to decode tx: {:?}", e))
            .map_err(RpcError::invalid_params)?;

        debug!("Deserialized tx: {:?}", tx);

        // TODO(thegaram): consider adding a light node specific tx pool;
        // light nodes would track those txs and maintain their statuses
        // for future queries

        match /* success = */ light.send_raw_tx(raw) {
            true => Ok(tx.hash().into()),
            false => Err(RpcError::invalid_params("Unable to relay tx")),
        }
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Self::send_tx_helper(self.light.clone(), raw)
    }

    fn send_transaction(
        &self, mut tx: SendTxRequest, password: Option<String>,
    ) -> BoxFuture<H256> {
        info!("RPC Request: cfx_sendTransaction tx={:?}", tx);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let accounts = self.accounts.clone();

        let fut = async move {
            if tx.nonce.is_none() {
                // TODO(thegaram): consider adding a light node specific tx pool
                // to track the nonce

                let address = tx.from.clone().into();
                let epoch = EpochNumber::LatestState.into_primitive();

                let nonce = light
                    .get_account(epoch, address)
                    .await
                    .map_err(|e| format!("failed to send transaction: {:?}", e))
                    .map_err(RpcError::invalid_params)?
                    .map(|a| a.nonce)
                    .unwrap_or(U256::zero());

                tx.nonce.replace(nonce.into());
                debug!("after loading nonce in latest state, tx = {:?}", tx);
            }

            let epoch_height = light.get_latest_verifiable_epoch_number().map_err(|_| {
                RpcError::invalid_params(format!("the light client cannot retrieve/verify the latest mined pivot block."))
            })?;
            let chain_id = light.get_latest_verifiable_chain_id().map_err(|_| {
                RpcError::invalid_params(format!("the light client cannot retrieve/verify the latest chain_id."))
            })?;
            let tx = tx
                .sign_with(epoch_height, chain_id, password, accounts)
                .map_err(|e| {
                RpcError::invalid_params(format!(
                    "failed to send transaction: {:?}",
                    e
                ))
            })?;

            Self::send_tx_helper(light, Bytes::new(tx.rlp_bytes()))
        };

        Box::new(fut.boxed().compat())
    }

    fn storage_root(
        &self, address: H160, epoch_num: Option<EpochNumber>,
    ) -> RpcBoxFuture<Option<RpcStorageRoot>> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageRoot address={:?} epoch={:?})",
            address, epoch_num
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let root = invalid_params_check(
                "address",
                light.get_storage_root(epoch_num.into(), address).await,
            )?;

            Ok(root.map(RpcStorageRoot::from_primitive))
        };

        Box::new(fut.boxed().compat())
    }

    fn storage_at(
        &self, address: H160, position: H256, epoch_num: Option<EpochNumber>,
    ) -> BoxFuture<Option<H256>> {
        let address: H160 = address.into();
        let position: H256 = position.into();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageAt address={:?} position={:?} epoch={:?})",
            address, position, epoch_num
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let maybe_entry = light
                .get_storage(epoch_num.into(), address, position)
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            Ok(maybe_entry.map(Into::into))
        };

        Box::new(fut.boxed().compat())
    }

    fn transaction_by_hash(
        &self, hash: H256,
    ) -> BoxFuture<Option<RpcTransaction>> {
        info!("RPC Request: cfx_getTransactionByHash hash={:?}", hash);

        // TODO(thegaram): try to retrieve from local tx pool or cache first

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let tx = light
                .get_tx(hash.into())
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            Ok(Some(RpcTransaction::from_signed(&tx, None)))
        };

        Box::new(fut.boxed().compat())
    }

    fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> BoxFuture<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt hash={:?}", hash);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            // FIXME: why not return an RpcReceipt directly?
            let (
                tx,
                receipt,
                address,
                maybe_epoch,
                maybe_state_root,
                prior_gas_used,
            ) = light
                .get_tx_info(hash)
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            let receipt = RpcReceipt::new(
                tx,
                receipt,
                address,
                prior_gas_used,
                maybe_epoch,
                maybe_state_root,
            );

            Ok(Some(receipt))
        };

        Box::new(fut.boxed().compat())
    }
}

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
            fn best_block_hash(&self) -> RpcResult<H256>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: H256, pivot_hash: H256, epoch_number: U64) -> RpcResult<RpcBlock>;
            fn block_by_hash(&self, hash: H256, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<H256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<U256>;
            fn gas_price(&self) -> RpcResult<U256>;
            fn next_nonce(&self, address: H160, num: Option<BlockHashOrEpochNumber>) -> RpcResult<U256>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<H256>>;
            fn confirmation_risk_by_hash(&self, block_hash: H256) -> RpcResult<Option<U256>>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn get_client_version(&self) -> RpcResult<String>;
        }

        to self.rpc_impl {
            fn account(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn admin(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<Option<H160>>;
            fn balance(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn call(&self, request: CallRequest, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn code(&self, address: H160, epoch_num: Option<EpochNumber>) -> BoxFuture<Bytes>;
            fn collateral_for_storage(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn estimate_gas_and_collateral(&self, request: CallRequest, epoch_num: Option<EpochNumber>) -> RpcResult<EstimateGasAndCollateralResponse>;
            fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256>;
            fn sponsor_info(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<RpcSponsorInfo>;
            fn staking_balance(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn storage_at(&self, addr: H160, pos: H256, epoch_number: Option<EpochNumber>) -> BoxFuture<Option<H256>>;
            fn storage_root(&self, address: H160, epoch_num: Option<EpochNumber>) -> BoxFuture<Option<RpcStorageRoot>>;
            fn transaction_by_hash(&self, hash: H256) -> BoxFuture<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: H256) -> BoxFuture<Option<RpcReceipt>>;
        }
    }

    not_supported! {
        fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<U256>;
        fn interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<U256>;
        fn check_balance_against_transaction(&self, account_addr: H160, contract_addr: H160, gas_limit: U256, gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>) -> RpcResult<CheckBalanceAgainstTransactionResponse>;
        fn get_block_reward_info(&self, num: EpochNumber) -> RpcResult<Vec<RpcRewardInfo>>;
    }
}

pub struct TestRpcImpl {
    common: Arc<CommonImpl>,
    // rpc_impl: Arc<RpcImpl>,
}

impl TestRpcImpl {
    pub fn new(common: Arc<CommonImpl>, _rpc_impl: Arc<RpcImpl>) -> Self {
        TestRpcImpl {
            common, /* , rpc_impl */
        }
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
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
            fn save_node_db(&self) -> RpcResult<()>;
        }
    }

    not_supported! {
        fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> RpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
        fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<H256>;
        fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256, timestamp: u64, adaptive: bool) -> RpcResult<H256>;
        fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
        fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;
        fn get_pivot_chain_and_weight(&self, height_range: Option<(u64, u64)>) -> RpcResult<Vec<(H256, U256)>>;
        fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)> ;
        fn send_usable_genesis_accounts(&self, account_start_index: usize) -> RpcResult<Bytes>;
        fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)>;
        fn set_db_crash(&self, crash_probability: f64, crash_exit_code: i32) -> RpcResult<()>;
    }
}

pub struct DebugRpcImpl {
    common: Arc<CommonImpl>,
    rpc_impl: Arc<RpcImpl>,
}

impl DebugRpcImpl {
    pub fn new(common: Arc<CommonImpl>, rpc_impl: Arc<RpcImpl>) -> Self {
        DebugRpcImpl { common, rpc_impl }
    }
}

impl LocalRpc for DebugRpcImpl {
    delegate! {
        to self.common {
            fn clear_tx_pool(&self) -> RpcResult<()>;
            fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> RpcResult<bool>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> RpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> RpcResult<throttling::Service>;
            fn tx_inspect(&self, hash: H256) -> RpcResult<BTreeMap<String, String>>;
            fn txpool_content(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txs_from_pool(&self) -> RpcResult<Vec<RpcTransaction>>;
            fn txpool_inspect(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;
            fn accounts(&self) -> RpcResult<Vec<H160>>;
            fn new_account(&self, password: String) -> RpcResult<H160>;
            fn unlock_account(&self, address: H160, password: String, duration: Option<U128>) -> RpcResult<bool>;
            fn lock_account(&self, address: H160) -> RpcResult<bool>;
            fn sign(&self, data: Bytes, address: H160, password: Option<String>) -> RpcResult<H520>;
        }

        to self.rpc_impl {
            fn send_transaction(&self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<H256>;
            fn sign_transaction(&self, tx: SendTxRequest, password: Option<String>) -> RpcResult<String>;
        }
    }

    not_supported! {
        fn current_sync_phase(&self) -> RpcResult<String>;
        fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
        fn sync_graph_state(&self) -> RpcResult<SyncGraphStates>;
    }
}
