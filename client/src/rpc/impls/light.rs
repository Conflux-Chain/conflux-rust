// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H160, H256, H520, U128, U256, U64};
use cfxcore::{
    block_data_manager::BlockDataManager,
    consensus_parameters::ONE_GDRIP_IN_DRIP,
    light_protocol::{query_service::TxInfo, Error as LightError, ErrorKind},
    rpc_errors::{account_result_to_rpc_result, invalid_params_check},
    ConsensusGraph, LightQueryService, PeerInfo, SharedConsensusGraph,
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
use primitives::{
    Account, DepositInfo, SponsorInfo, StorageRoot, TransactionWithSignature,
    VoteStakeInfo,
};
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
            SendTxRequest, Status as RpcStatus, SyncGraphStates,
            Transaction as RpcTransaction, TxPoolPendingInfo, TxWithPoolInfo,
        },
        RpcBoxFuture,
    },
};

// macro for reducing boilerplate for unsupported methods
#[macro_use]
macro_rules! not_supported {
    () => {};
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> BoxFuture<$ret:ty> )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> BoxFuture<$ret> )? {
            use jsonrpc_core::futures::future::{Future, IntoFuture};
            Err(error_codes::unimplemented(Some("Tracking issue: https://github.com/Conflux-Chain/conflux-rust/issues/1461".to_string())))
                .into_future()
                .boxed()
        }

        not_supported!($($tail)*);
    };
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> $ret:ty )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> $ret )? {
            Err(error_codes::unimplemented(Some("Tracking issue: https://github.com/Conflux-Chain/conflux-rust/issues/1461".to_string())))
        }

        not_supported!($($tail)*);
    };
}

pub struct RpcImpl {
    // account provider used for signing transactions
    accounts: Arc<AccountProvider>,

    // configuration parameters
    config: RpcImplConfiguration,

    // consensus graph
    consensus: SharedConsensusGraph,

    // block data manager
    data_man: Arc<BlockDataManager>,

    // helper API for retrieving verified information from peers
    light: Arc<LightQueryService>,
}

impl RpcImpl {
    pub fn new(
        config: RpcImplConfiguration, light: Arc<LightQueryService>,
        accounts: Arc<AccountProvider>, consensus: SharedConsensusGraph,
        data_man: Arc<BlockDataManager>,
    ) -> Self
    {
        RpcImpl {
            accounts,
            config,
            consensus,
            data_man,
            light,
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
    ) -> RpcBoxFuture<SponsorInfo> {
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

            Ok(account.map_or(Default::default(), |acc| acc.sponsor_info))
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

    fn deposit_list(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<Vec<DepositInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getDepositList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let mut result = vec![];
            if let Some(deposit_list) = invalid_params_check(
                "address",
                light.get_deposit_list(epoch, address).await,
            )? {
                result = (*deposit_list).clone();
            }

            Ok(result)
        };

        Box::new(fut.boxed().compat())
    }

    fn vote_list(
        &self, address: H160, num: Option<EpochNumber>,
    ) -> RpcBoxFuture<Vec<VoteStakeInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        info!(
            "RPC Request: cfx_getVoteList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            let mut result = vec![];
            if let Some(vote_list) = invalid_params_check(
                "address",
                light.get_vote_list(epoch, address).await,
            )? {
                result = (*vote_list).clone();
            }

            Ok(result)
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
    ) -> RpcBoxFuture<Option<StorageRoot>> {
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

            Ok(Some(root))
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
            // TODO:
            //  return an RpcReceipt directly after splitting cfxcore into
            //  smaller crates. It's impossible now because of circular
            //  dependency.

            // return `null` on timeout
            let tx_info = match light.get_tx_info(hash).await {
                Ok(t) => t,
                Err(LightError(ErrorKind::Timeout(_), _)) => return Ok(None),
                Err(LightError(e, _)) => {
                    return Err(RpcError::invalid_params(e.to_string()))
                }
            };

            let TxInfo {
                tx,
                maybe_block_number,
                receipt,
                tx_index,
                maybe_epoch,
                maybe_state_root,
                prior_gas_used,
            } = tx_info;

            if maybe_block_number.is_none() {
                return Ok(None);
            }

            let receipt = RpcReceipt::new(
                tx,
                receipt,
                tx_index,
                prior_gas_used,
                maybe_epoch,
                maybe_block_number.unwrap(),
                maybe_state_root,
                // Can not offer error_message from light node.
                None,
            );

            Ok(Some(receipt))
        };

        Box::new(fut.boxed().compat())
    }

    pub fn epoch_number(&self, epoch: Option<EpochNumber>) -> RpcResult<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber epoch={:?}", epoch);

        match self.light.get_height_from_epoch_number(epoch.into()) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e.to_string())),
        }
    }

    pub fn next_nonce(
        &self, address: H160, num: Option<BlockHashOrEpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let address: H160 = address.into();

        info!(
            "RPC Request: cfx_getNextNonce address={:?} num={:?}",
            address, num
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let light = self.light.clone();

        let fut = async move {
            let epoch = match num {
                None => EpochNumber::LatestState,
                Some(BlockHashOrEpochNumber::EpochNumber(e)) => e,
                Some(BlockHashOrEpochNumber::BlockHash(h)) => consensus_graph
                    .get_block_epoch_number(&h)
                    .map(Into::into)
                    .map(EpochNumber::Num)
                    .ok_or(RpcError::invalid_params(
                        "Cannot find epoch corresponding to block hash",
                    ))?,
            }
            .into();

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address).await,
            )?;

            Ok(account
                .map(|account| account.nonce.into())
                .unwrap_or_default())
        };

        Box::new(fut.boxed().compat())
    }

    pub fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> RpcBoxFuture<Option<RpcBlock>> {
        let hash = hash.into();

        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let data_man = self.data_man.clone();
        let light = self.light.clone();

        let fut = async move {
            let block = match light.retrieve_block(hash).await? {
                None => return Ok(None),
                Some(b) => b,
            };

            let inner = consensus_graph
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
                .inner
                .read();

            Ok(Some(RpcBlock::new(&block, &*inner, &data_man, include_txs)))
        };

        Box::new(fut.boxed().compat())
    }

    pub fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> RpcBoxFuture<RpcBlock> {
        let block_hash = block_hash.into();
        let pivot_hash = pivot_hash.into();
        let epoch_number = epoch_number.as_u64();

        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let data_man = self.data_man.clone();
        let light = self.light.clone();

        let fut = async move {
            // check pivot assumption
            // make sure not to hold the lock through await's
            consensus_graph
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
                .inner
                .read()
                .check_block_pivot_assumption(&pivot_hash, epoch_number)
                .map_err(RpcError::invalid_params)?;

            // retrieve block body
            let block = light
                .retrieve_block(block_hash)
                .await?
                .ok_or_else(|| RpcError::invalid_params("Block not found"))?;

            let inner = consensus_graph
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
                .inner
                .read();

            Ok(RpcBlock::new(&block, &*inner, &data_man, true))
        };

        Box::new(fut.boxed().compat())
    }

    pub fn block_by_epoch_number(
        &self, epoch: EpochNumber, include_txs: bool,
    ) -> RpcBoxFuture<Option<RpcBlock>> {
        info!(
            "RPC Request: cfx_getBlockByEpochNumber epoch={:?} include_txs={:?}",
            epoch, include_txs
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let data_man = self.data_man.clone();
        let light = self.light.clone();

        let fut = async move {
            let epoch: u64 = light
                .get_height_from_epoch_number(epoch.into())
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?;

            // make sure not to hold the lock through await's
            let hash = consensus_graph
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
                .inner
                .read()
                .get_pivot_hash_from_epoch_number(epoch)
                .map_err(RpcError::invalid_params)?;

            // retrieve block body
            let block = match light.retrieve_block(hash).await? {
                None => return Ok(None),
                Some(b) => b,
            };

            let inner = consensus_graph
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
                .inner
                .read();

            Ok(Some(RpcBlock::new(&block, &*inner, &data_man, include_txs)))
        };

        Box::new(fut.boxed().compat())
    }

    pub fn blocks_by_epoch(&self, epoch: EpochNumber) -> RpcResult<Vec<H256>> {
        info!("RPC Request: cfx_getBlocksByEpoch epoch_number={:?}", epoch);

        let height = self
            .light
            .get_height_from_epoch_number(epoch.into())
            .map_err(|e| e.to_string())
            .map_err(RpcError::invalid_params)?;

        let hashes = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
            .inner
            .read()
            .block_hashes_by_epoch(height)
            .map_err(|e| e.to_string())
            .map_err(RpcError::invalid_params)?;

        Ok(hashes)
    }

    pub fn gas_price(&self) -> RpcBoxFuture<U256> {
        info!("RPC Request: cfx_gasPrice");

        let light = self.light.clone();

        let fut = async move {
            Ok(light
                .gas_price()
                .await
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?
                .unwrap_or(ONE_GDRIP_IN_DRIP.into()))
        };

        Box::new(fut.boxed().compat())
    }

    pub fn interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();
        info!("RPC Request: cfx_getInterestRate epoch={:?}", epoch);

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Ok(light
                .get_interest_rate(epoch)
                .await
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?)
        };

        Box::new(fut.boxed().compat())
    }

    pub fn accumulate_interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcBoxFuture<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAccumulateInterestRate epoch={:?}",
            epoch
        );

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Ok(light
                .get_accumulate_interest_rate(epoch)
                .await
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?)
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
            fn confirmation_risk_by_hash(&self, block_hash: H256) -> RpcResult<Option<U256>>;
            fn get_client_version(&self) -> RpcResult<String>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<H256>>;
        }

        to self.rpc_impl {
            fn account(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
            fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn admin(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<Option<H160>>;
            fn balance(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> BoxFuture<Option<RpcBlock>>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: H256, pivot_hash: H256, epoch_number: U64) -> BoxFuture<RpcBlock>;
            fn block_by_hash(&self, hash: H256, include_txs: bool) -> BoxFuture<Option<RpcBlock>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<H256>>;
            fn code(&self, address: H160, epoch_num: Option<EpochNumber>) -> BoxFuture<Bytes>;
            fn collateral_for_storage(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<U256>;
            fn gas_price(&self) -> BoxFuture<U256>;
            fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
            fn interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn next_nonce(&self, address: H160, num: Option<BlockHashOrEpochNumber>) -> BoxFuture<U256>;
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256>;
            fn sponsor_info(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<SponsorInfo>;
            fn staking_balance(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<U256>;
            fn deposit_list(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<Vec<DepositInfo>>;
            fn vote_list(&self, address: H160, num: Option<EpochNumber>) -> BoxFuture<Vec<VoteStakeInfo>>;
            fn storage_at(&self, addr: H160, pos: H256, epoch_number: Option<EpochNumber>) -> BoxFuture<Option<H256>>;
            fn storage_root(&self, address: H160, epoch_num: Option<EpochNumber>) -> BoxFuture<Option<StorageRoot>>;
            fn transaction_by_hash(&self, hash: H256) -> BoxFuture<Option<RpcTransaction>>;
            fn transaction_receipt(&self, tx_hash: H256) -> BoxFuture<Option<RpcReceipt>>;
        }
    }

    // TODO(thegaram): add support for these
    not_supported! {
        fn call(&self, request: CallRequest, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
        fn check_balance_against_transaction(&self, account_addr: H160, contract_addr: H160, gas_limit: U256, gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>) -> RpcResult<CheckBalanceAgainstTransactionResponse>;
        fn estimate_gas_and_collateral(&self, request: CallRequest, epoch_num: Option<EpochNumber>) -> RpcResult<EstimateGasAndCollateralResponse>;
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
            fn save_node_db(&self) -> RpcResult<()>;
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
        }
    }

    not_supported! {
        fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> RpcResult<H256>;
        fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256, timestamp: u64, adaptive: bool) -> RpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
        fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
        fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<H256>;
        fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
        fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)>;
        fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)> ;
        fn get_pivot_chain_and_weight(&self, height_range: Option<(u64, u64)>) -> RpcResult<Vec<(H256, U256)>>;
        fn send_usable_genesis_accounts(&self, account_start_index: usize) -> RpcResult<Bytes>;
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
            fn accounts(&self) -> RpcResult<Vec<H160>>;
            fn clear_tx_pool(&self) -> RpcResult<()>;
            fn lock_account(&self, address: H160) -> RpcResult<bool>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> RpcResult<bool>;
            fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> RpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> RpcResult<throttling::Service>;
            fn new_account(&self, password: String) -> RpcResult<H160>;
            fn sign(&self, data: Bytes, address: H160, password: Option<String>) -> RpcResult<H520>;
            fn tx_inspect_pending(&self, address: H160) -> RpcResult<TxPoolPendingInfo>;
            fn tx_inspect(&self, hash: H256) -> RpcResult<TxWithPoolInfo>;
            fn txpool_content(&self, address: Option<H160>) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self, address: Option<H160>) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;
            fn txs_from_pool(&self, address: Option<H160>) -> RpcResult<Vec<RpcTransaction>>;
            fn unlock_account(&self, address: H160, password: String, duration: Option<U128>) -> RpcResult<bool>;
        }

        to self.rpc_impl {
            fn send_transaction(&self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<H256>;
        }
    }

    not_supported! {
        fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
        fn current_sync_phase(&self) -> RpcResult<String>;
        fn sign_transaction(&self, tx: SendTxRequest, password: Option<String>) -> RpcResult<String>;
        fn sync_graph_state(&self) -> RpcResult<SyncGraphStates>;
    }
}
