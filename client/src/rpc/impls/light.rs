// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::common::RpcImpl as CommonImpl;
use crate::rpc::{
    traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
    types::{
        Account as RpcAccount, BlameInfo, Block as RpcBlock,
        BlockHashOrEpochNumber, Bytes, CallRequest, ConsensusGraphStates,
        EpochNumber, EstimateGasAndCollateralResponse, Filter as RpcFilter,
        Log as RpcLog, Receipt as RpcReceipt, SendTxRequest,
        SponsorInfo as RpcSponsorInfo, Status as RpcStatus, SyncGraphStates,
        Transaction as RpcTransaction, H160 as RpcH160, H256 as RpcH256,
        H520 as RpcH520, U128 as RpcU128, U256 as RpcU256, U64 as RpcU64,
    },
};
use cfx_types::{H160, H256, U256};
use cfxcore::{LightQueryService, PeerInfo};
use delegate::delegate;
use futures::future::{FutureExt, TryFutureExt};
use jsonrpc_core::{BoxFuture, Error as RpcError, Result as RpcResult};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use primitives::{Account, TransactionWithSignature};
use rlp::Encodable;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

pub struct RpcImpl {
    // helper API for retrieving verified information from peers
    light: Arc<LightQueryService>,
}

impl RpcImpl {
    pub fn new(light: Arc<LightQueryService>) -> Self { RpcImpl { light } }

    fn account(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcAccount> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getAccount address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(RpcAccount::new(account.unwrap_or(
                Account::new_empty_with_balance(
                    &address,
                    &U256::zero(), /* balance */
                    &U256::zero(), /* nonce */
                ),
            )))
        };

        Box::new(fut.boxed().compat())
    }

    fn balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcU256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(account
                .map(|account| account.balance.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    fn admin(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcH160> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(account
                .map(|account| account.admin.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    fn sponsor_info(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcSponsorInfo> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(RpcSponsorInfo::new(
                account.map_or(Default::default(), |acc| acc.sponsor_info),
            ))
        };

        Box::new(fut.boxed().compat())
    }

    fn staking_balance(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcU256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(account
                .map(|account| account.staking_balance.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    fn collateral_for_storage(
        &self, address: RpcH160, num: Option<EpochNumber>,
    ) -> BoxFuture<RpcU256> {
        let address: H160 = address.into();
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let account = light
                .get_account(epoch, address)
                .await
                .map_err(RpcError::invalid_params)?;

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
        // TODO
        unimplemented!()
    }

    fn code(
        &self, address: RpcH160, epoch_num: Option<EpochNumber>,
    ) -> BoxFuture<Bytes> {
        let address: H160 = address.into();
        let epoch = epoch_num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCode address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            light
                .get_code(epoch, address)
                .await
                .map(|code| code.unwrap_or_default())
                .map(Bytes::new)
                .map_err(RpcError::invalid_params)
        };

        Box::new(fut.boxed().compat())
    }

    #[allow(unused_variables)]
    fn estimate_gas_and_collateral(
        &self, request: CallRequest, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        // TODO
        unimplemented!()
    }

    fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>> {
        info!("RPC Request: cfx_getLogs({:?})", filter);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let logs = light
                .get_logs(filter.into())
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(logs.into_iter().map(RpcLog::from).collect())
        };

        Box::new(fut.boxed().compat())
    }

    fn send_tx_helper(
        light: Arc<LightQueryService>, raw: Bytes,
    ) -> RpcResult<RpcH256> {
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

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Self::send_tx_helper(self.light.clone(), raw)
    }

    fn send_transaction(
        &self, mut tx: SendTxRequest, password: Option<String>,
    ) -> BoxFuture<RpcH256> {
        info!("RPC Request: send_transaction, tx = {:?}", tx);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

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
            let tx = tx.sign_with(epoch_height, chain_id, password).map_err(
                |e| {
                    RpcError::invalid_params(format!(
                        "failed to send transaction: {:?}",
                        e
                    ))
                },
            )?;

            Self::send_tx_helper(light, Bytes::new(tx.rlp_bytes()))
        };

        Box::new(fut.boxed().compat())
    }

    fn storage_at(
        &self, address: RpcH160, position: RpcH256,
        epoch_num: Option<EpochNumber>,
    ) -> BoxFuture<Option<RpcH256>>
    {
        let address: H160 = address.into();
        let position: H256 = position.into();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageAt address={:?}, position={:?}, epoch_num={:?})",
            address, position, epoch_num
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let maybe_entry = light
                .get_storage(epoch_num.into(), address, position)
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(maybe_entry.map(Into::into))
        };

        Box::new(fut.boxed().compat())
    }

    fn transaction_by_hash(
        &self, hash: RpcH256,
    ) -> BoxFuture<Option<RpcTransaction>> {
        info!("RPC Request: cfx_getTransactionByHash({:?})", hash);

        // TODO(thegaram): try to retrieve from local tx pool or cache first

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let tx = light
                .get_tx(hash.into())
                .await
                .map_err(RpcError::invalid_params)?;

            Ok(Some(RpcTransaction::from_signed(&tx, None)))
        };

        Box::new(fut.boxed().compat())
    }

    fn transaction_receipt(
        &self, tx_hash: RpcH256,
    ) -> BoxFuture<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt({:?})", hash);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
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
                .map_err(RpcError::invalid_params)?;

            let mut receipt =
                RpcReceipt::new(tx, receipt, address, prior_gas_used);
            receipt.set_epoch_number(maybe_epoch);

            if let Some(state_root) = maybe_state_root {
                receipt.set_state_root(state_root.into());
            }

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
        target self.common {
            fn best_block_hash(&self) -> RpcResult<RpcH256>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> RpcResult<RpcBlock>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64) -> RpcResult<RpcBlock>;
            fn block_by_hash(&self, hash: RpcH256, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<RpcU256>;
            fn gas_price(&self) -> RpcResult<RpcU256>;
            fn next_nonce(&self, address: RpcH160, num: Option<BlockHashOrEpochNumber>) -> RpcResult<RpcU256>;
        }

        target self.rpc_impl {
            fn account(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            fn staking_balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            fn collateral_for_storage(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
            fn admin(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcH160>;
            fn sponsor_info(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcSponsorInfo>;
            fn call(&self, request: CallRequest, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
            fn code(&self, address: RpcH160, epoch_num: Option<EpochNumber>) -> BoxFuture<Bytes>;
            fn estimate_gas_and_collateral(&self, request: CallRequest, epoch_num: Option<EpochNumber>) -> RpcResult<EstimateGasAndCollateralResponse>;
            fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256>;
            fn storage_at(&self, addr: RpcH160, pos: RpcH256, epoch_number: Option<EpochNumber>) -> BoxFuture<Option<RpcH256>>;
            fn transaction_by_hash(&self, hash: RpcH256) -> BoxFuture<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: RpcH256) -> BoxFuture<Option<RpcReceipt>>;
        }
    }

    not_supported! {
        fn interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
        fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
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
        target self.common {
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
    }

    not_supported! {
        fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> RpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
        fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<()>;
        fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: u64, timestamp: u64, adaptive: bool) -> RpcResult<H256>;
        fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
        fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;
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
        target self.common {
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

        target self.rpc_impl {
            fn send_transaction(&self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<RpcH256>;
        }
    }

    not_supported! {
        fn current_sync_phase(&self) -> RpcResult<String>;
        fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
        fn sync_graph_state(&self) -> RpcResult<SyncGraphStates>;
    }
}
