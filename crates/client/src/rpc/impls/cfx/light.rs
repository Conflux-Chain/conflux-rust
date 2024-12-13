// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{
    AddressSpaceUtil, BigEndianHash, Space, H160, H256, H520, U128, U256, U64,
};
use cfx_util_macros::bail;
use cfxcore::{
    block_data_manager::BlockDataManager,
    consensus::ConsensusConfig,
    errors::account_result_to_rpc_result,
    light_protocol::{self, query_service::TxInfo, Error as LightError},
    verification::EpochReceiptProof,
    ConsensusGraph, ConsensusGraphTrait, LightQueryService, PeerInfo,
    SharedConsensusGraph,
};
use cfxcore_accounts::AccountProvider;
use delegate::delegate;
use diem_types::transaction::TransactionPayload;
use futures::future::{self, FutureExt};
use jsonrpc_core::{BoxFuture, Error as RpcError, Result as JsonRpcResult};
use log::{debug, info};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use primitives::{
    Account, DepositInfo, StorageRoot, TransactionWithSignature, VoteStakeInfo,
};
use rlp::Encodable;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};
// To convert from CoreResult to BoxFuture by delegate! macro automatically.
use crate::{
    common::delegate_convert,
    rpc::{
        errors::{self, invalid_params_check},
        helpers::MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
        impls::common::{self, RpcImpl as CommonImpl},
        traits::{cfx::Cfx, debug::LocalRpc, test::TestRpc},
        types::{
            cfx::check_rpc_address_network,
            pos::{Block as PosBlock, PoSEpochReward},
            Account as RpcAccount, AccountPendingInfo,
            AccountPendingTransactions, BlameInfo, Block as RpcBlock,
            BlockHashOrEpochNumber, Bytes, CfxFeeHistory, CfxRpcLogFilter,
            CheckBalanceAgainstTransactionResponse, ConsensusGraphStates,
            EpochNumber, EstimateGasAndCollateralResponse, FeeHistory,
            Log as RpcLog, PoSEconomics, Receipt as RpcReceipt,
            RewardInfo as RpcRewardInfo, RpcAddress, SponsorInfo,
            StatOnGasLoad, Status as RpcStatus, StorageCollateralInfo,
            SyncGraphStates, TokenSupplyInfo, Transaction as RpcTransaction,
            TransactionRequest, VoteParamsInfo, WrapTransaction, U64 as HexU64,
        },
        CoreBoxFuture, CoreResult,
    },
};
use cfx_addr::Network;
use cfx_parameters::rpc::GAS_PRICE_DEFAULT_VALUE;
use cfxcore::{errors::Error::LightProtocol, light_protocol::QueryService};
use diem_types::account_address::AccountAddress;

// macro for reducing boilerplate for unsupported methods
macro_rules! not_supported {
    () => {};
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> BoxFuture<$ret:ty> )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> BoxFuture<$ret> )? {
            async {
                Err(errors::unimplemented(Some("Tracking issue: https://github.com/Conflux-Chain/conflux-rust/issues/1461".to_string())))
            }.boxed()
        }

        not_supported!($($tail)*);
    };
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> $ret:ty )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> $ret )? {
            Err(errors::unimplemented(Some("Tracking issue: https://github.com/Conflux-Chain/conflux-rust/issues/1461".to_string())))
        }

        not_supported!($($tail)*);
    };
}

pub struct RpcImpl {
    // account provider used for signing transactions
    accounts: Arc<AccountProvider>,

    // consensus graph
    consensus: SharedConsensusGraph,

    // block data manager
    data_man: Arc<BlockDataManager>,

    // helper API for retrieving verified information from peers
    light: Arc<LightQueryService>,
}

impl RpcImpl {
    pub fn new(
        light: Arc<LightQueryService>, accounts: Arc<AccountProvider>,
        consensus: SharedConsensusGraph, data_man: Arc<BlockDataManager>,
    ) -> Self {
        RpcImpl {
            accounts,
            consensus,
            data_man,
            light,
        }
    }

    fn check_address_network(
        network: Network, light: &QueryService,
    ) -> CoreResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(Some(network), light.get_network_type()),
        )
        .map_err(|e| e.into())
    }

    fn get_epoch_number_with_pivot_check(
        consensus_graph: SharedConsensusGraph,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> CoreResult<EpochNumber> {
        match block_hash_or_epoch_number {
            Some(BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            }) => {
                let epoch_number = consensus_graph
                    .as_any()
                    .downcast_ref::<ConsensusGraph>()
                    .expect("downcast should succeed")
                    .get_block_epoch_number_with_pivot_check(
                        &hash,
                        require_pivot.unwrap_or(true),
                    )?;
                Ok(EpochNumber::Num(U64::from(epoch_number)))
            }
            Some(BlockHashOrEpochNumber::EpochNumber(epoch_number)) => {
                Ok(epoch_number)
            }
            None => Ok(EpochNumber::LatestState),
        }
    }

    fn account(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<RpcAccount> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAccount address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;
            let network = address.network;

            let account = invalid_params_check(
                "epoch",
                light.get_account(epoch, address.hex_address).await,
            )?;

            let account = account.unwrap_or(account_result_to_rpc_result(
                "address",
                Ok(Account::new_empty_with_balance(
                    &address.hex_address.with_native_space(),
                    &U256::zero(), /* balance */
                    &U256::zero(), /* nonce */
                )),
            )?);

            Ok(RpcAccount::try_from(account, network)?)
        };

        fut.boxed()
    }

    fn balance(
        &self, address: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> CoreBoxFuture<U256> {
        info!(
            "RPC Request: cfx_getBalance address={:?} epoch={:?}",
            address,
            block_hash_or_epoch_number
                .as_ref()
                .ok_or(EpochNumber::LatestState)
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let consensus_graph = self.consensus.clone();

        let fut = async move {
            let epoch = Self::get_epoch_number_with_pivot_check(
                consensus_graph,
                block_hash_or_epoch_number,
            )?
            .into();
            Self::check_address_network(address.network, &light)?;

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            Ok(account
                .map(|account| account.balance.into())
                .unwrap_or_default())
        };

        fut.boxed()
    }

    fn admin(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<Option<RpcAddress>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            match account {
                None => Ok(None),
                Some(acc) => {
                    Ok(Some(RpcAddress::try_from_h160(acc.admin, network)?))
                }
            }
        };

        fut.boxed()
    }

    fn sponsor_info(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<SponsorInfo> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;
            let network = address.network;

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            match account {
                None => Ok(SponsorInfo::default(network)?),
                Some(acc) => {
                    Ok(SponsorInfo::try_from(acc.sponsor_info, network)?)
                }
            }
        };

        fut.boxed()
    }

    fn staking_balance(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<U256> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            Ok(account
                .map(|account| account.staking_balance.into())
                .unwrap_or_default())
        };

        fut.boxed()
    }

    fn deposit_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<Vec<DepositInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getDepositList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let maybe_list = invalid_params_check(
                "address",
                light.get_deposit_list(epoch, address.into()).await,
            )?;

            match maybe_list {
                None => Ok(vec![]),
                Some(deposit_list) => Ok(deposit_list.0),
            }
        };

        fut.boxed()
    }

    pub fn account_pending_info(
        &self, address: RpcAddress,
    ) -> CoreBoxFuture<Option<AccountPendingInfo>> {
        info!("RPC Request: cfx_getAccountPendingInfo({:?})", address);

        let fut = async move {
            // TODO impl light node rpc
            Ok(None)
        };
        fut.boxed()
    }

    fn vote_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<Vec<VoteStakeInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getVoteList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let maybe_list = invalid_params_check(
                "address",
                light.get_vote_list(epoch, address.into()).await,
            )?;

            match maybe_list {
                None => Ok(vec![]),
                Some(vote_list) => Ok(vote_list.0),
            }
        };

        fut.boxed()
    }

    fn collateral_for_storage(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> CoreBoxFuture<U256> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            Ok(account
                .map(|account| account.collateral_for_storage.into())
                .unwrap_or_default())
        };

        fut.boxed()
    }

    fn code(
        &self, address: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> CoreBoxFuture<Bytes> {
        info!(
            "RPC Request: cfx_getCode address={:?} epoch={:?}",
            address,
            block_hash_or_epoch_number
                .as_ref()
                .ok_or(EpochNumber::LatestState)
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let consensus_graph = self.consensus.clone();

        let fut = async move {
            let epoch = Self::get_epoch_number_with_pivot_check(
                consensus_graph,
                block_hash_or_epoch_number,
            )?
            .into();
            Self::check_address_network(address.network, &light)?;

            // FIMXE:
            //  We should get rid of the invalid_params_check when the
            //  error conversion is done within the light service methods.
            //  Same for all other usages here in this file.
            Ok(Bytes::new(
                invalid_params_check(
                    "address",
                    light.get_code(epoch, address.into()).await,
                )?
                .unwrap_or_default(),
            ))
        };

        fut.boxed()
    }

    fn get_logs(&self, filter: CfxRpcLogFilter) -> CoreBoxFuture<Vec<RpcLog>> {
        info!("RPC Request: cfx_getLogs filter={:?}", filter);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            // all addresses specified should be for the correct network
            if let Some(addresses) = &filter.address {
                for address in addresses.iter() {
                    invalid_params_check(
                        "filter.address",
                        check_rpc_address_network(
                            Some(address.network),
                            light.get_network_type(),
                        ),
                    )?;
                }
            }

            let filter = filter.into_primitive()?;

            let logs = light
                .get_logs(filter)
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            Ok(logs
                .into_iter()
                .map(|l| {
                    RpcLog::try_from_localized(l, *light.get_network_type())
                })
                .collect::<Result<_, _>>()?)
        };

        fut.boxed()
    }

    fn send_tx_helper(
        light: Arc<LightQueryService>, raw: Bytes,
    ) -> CoreResult<H256> {
        let raw: Vec<u8> = raw.into_vec();

        // decode tx so that we have its hash
        // this way we also avoid spamming peers with invalid txs
        let tx: TransactionWithSignature =
            TransactionWithSignature::from_raw(&raw.clone())
                .map_err(|e| format!("Failed to decode tx: {:?}", e))
                .map_err(RpcError::invalid_params)?;

        debug!("Deserialized tx: {:?}", tx);

        // TODO(thegaram): consider adding a light node specific tx pool;
        // light nodes would track those txs and maintain their statuses
        // for future queries

        match /* success = */ light.send_raw_tx(raw) {
            true => Ok(tx.hash().into()),
            false => bail!(LightProtocol(light_protocol::Error::InternalError("Unable to relay tx".into()).into())),
        }
    }

    fn send_raw_transaction(&self, raw: Bytes) -> CoreResult<H256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Self::send_tx_helper(self.light.clone(), raw)
    }

    fn send_transaction(
        &self, mut tx: TransactionRequest, password: Option<String>,
    ) -> CoreBoxFuture<H256> {
        info!("RPC Request: cfx_sendTransaction tx={:?}", tx);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let accounts = self.accounts.clone();

        let fut = async move {
            tx.check_rpc_address_network("tx", light.get_network_type())?;

            if tx.nonce.is_none() {
                // TODO(thegaram): consider adding a light node specific tx pool
                // to track the nonce

                let address =
                    tx.from.clone().ok_or("from should exist")?.into();
                let epoch = EpochNumber::LatestState.into_primitive();

                let nonce = light
                    .get_account(epoch, address)
                    .await?
                    .map(|a| a.nonce)
                    .unwrap_or(U256::zero());

                tx.nonce.replace(nonce.into());
                debug!("after loading nonce in latest state, tx = {:?}", tx);
            }

            let epoch_height = light.get_latest_verifiable_epoch_number().map_err(|_| {
               format!("the light client cannot retrieve/verify the latest mined pivot block.")
            })?;
            let chain_id = light.get_latest_verifiable_chain_id().map_err(|_| {
                format!("the light client cannot retrieve/verify the latest chain_id.")
            })?;
            let tx = tx.sign_with(
                epoch_height,
                chain_id.in_native_space(),
                password,
                accounts,
            )?;

            Self::send_tx_helper(light, Bytes::new(tx.rlp_bytes()))
        };

        fut.boxed()
    }

    fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> CoreBoxFuture<Option<StorageRoot>> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageRoot address={:?} epoch={:?})",
            address, epoch_num
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let root = invalid_params_check(
                "address",
                light
                    .get_storage_root(epoch_num.into(), address.into())
                    .await,
            )?;

            Ok(Some(root))
        };

        fut.boxed()
    }

    fn storage_at(
        &self, address: RpcAddress, position: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> CoreBoxFuture<Option<H256>> {
        let position: H256 = H256::from_uint(&position);
        // let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageAt address={:?} position={:?} epoch={:?})",
            address,
            position,
            block_hash_or_epoch_number
                .as_ref()
                .ok_or(EpochNumber::LatestState)
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let consensus_graph = self.consensus.clone();

        let fut = async move {
            let epoch_num = Self::get_epoch_number_with_pivot_check(
                consensus_graph,
                block_hash_or_epoch_number,
            )?;
            Self::check_address_network(address.network, &light)?;

            let maybe_entry = light
                .get_storage(epoch_num.into(), address.into(), position)
                .await
                .map_err(|e| e.to_string()) // TODO(thegaram): return meaningful error
                .map_err(RpcError::invalid_params)?;

            Ok(maybe_entry.map(Into::into))
        };

        fut.boxed()
    }

    fn transaction_by_hash(
        &self, hash: H256,
    ) -> CoreBoxFuture<Option<RpcTransaction>> {
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

            Ok(Some(RpcTransaction::from_signed(
                &tx,
                None,
                *light.get_network_type(),
            )?))
        };

        fut.boxed()
    }

    fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> CoreBoxFuture<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt hash={:?}", hash);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let data_man = self.data_man.clone();

        let fut = async move {
            // TODO:
            //  return an RpcReceipt directly after splitting cfxcore into
            //  smaller crates. It's impossible now because of circular
            //  dependency.

            // return `null` on timeout
            let tx_info = match light.get_tx_info(hash).await {
                Ok(t) => t,
                Err(LightError::Timeout(_)) => return Ok(None),
                Err(e) => {
                    bail!(RpcError::invalid_params(e.to_string()))
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

            if maybe_block_number.is_none() || tx_index.is_phantom {
                return Ok(None);
            }

            let maybe_base_price = data_man
                .block_header_by_hash(&tx_index.block_hash)
                .and_then(|x| x.base_price());

            let receipt = RpcReceipt::new(
                tx,
                receipt,
                tx_index,
                prior_gas_used,
                maybe_epoch,
                maybe_block_number.unwrap(),
                maybe_base_price,
                maybe_state_root,
                // Can not offer error_message from light node.
                None,
                *light.get_network_type(),
                false,
                false,
            )?;

            Ok(Some(receipt))
        };

        fut.boxed()
    }

    pub fn epoch_number(&self, epoch: Option<EpochNumber>) -> CoreResult<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber epoch={:?}", epoch);

        invalid_params_check(
            "epoch",
            self.light
                .get_height_from_epoch_number(epoch.into())
                .map(|height| height.into()),
        )
        .map_err(|e| e.into())
    }

    pub fn next_nonce(
        &self, address: RpcAddress, num: Option<BlockHashOrEpochNumber>,
    ) -> CoreBoxFuture<U256> {
        info!(
            "RPC Request: cfx_getNextNonce address={:?} num={:?}",
            address, num
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(address.network, &light)?;

            let epoch =
                Self::get_epoch_number_with_pivot_check(consensus_graph, num)?
                    .into();

            let account = invalid_params_check(
                "address",
                light.get_account(epoch, address.into()).await,
            )?;

            Ok(account
                .map(|account| account.nonce.into())
                .unwrap_or_default())
        };

        fut.boxed()
    }

    pub fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> CoreBoxFuture<Option<RpcBlock>> {
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

            Ok(Some(RpcBlock::new(
                &block,
                *light.get_network_type(),
                &*consensus_graph,
                &*inner,
                &data_man,
                include_txs,
                Some(Space::Native),
            )?))
        };

        fut.boxed()
    }

    pub fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> CoreBoxFuture<RpcBlock> {
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

            Ok(RpcBlock::new(
                &block,
                *light.get_network_type(),
                &*consensus_graph,
                &*inner,
                &data_man,
                true,
                Some(Space::Native),
            )?)
        };

        fut.boxed()
    }

    pub fn block_by_epoch_number(
        &self, epoch: EpochNumber, include_txs: bool,
    ) -> CoreBoxFuture<Option<RpcBlock>> {
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

            Ok(Some(RpcBlock::new(
                &block,
                *light.get_network_type(),
                &*consensus_graph,
                &*inner,
                &data_man,
                include_txs,
                Some(Space::Native),
            )?))
        };

        fut.boxed()
    }

    pub fn blocks_by_epoch(&self, epoch: EpochNumber) -> CoreResult<Vec<H256>> {
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

    pub fn gas_price(&self) -> CoreBoxFuture<U256> {
        info!("RPC Request: cfx_gasPrice");

        let light = self.light.clone();

        let fut = async move {
            Ok(light
                .gas_price()
                .await
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?
                .unwrap_or(GAS_PRICE_DEFAULT_VALUE.into()))
        };

        fut.boxed()
    }

    pub fn interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> CoreBoxFuture<U256> {
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

        fut.boxed()
    }

    pub fn accumulate_interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> CoreBoxFuture<U256> {
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

        fut.boxed()
    }

    pub fn pos_economics(
        &self, epoch: Option<EpochNumber>,
    ) -> CoreBoxFuture<PoSEconomics> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();

        info!("RPC Request: cfx_getPoSEconomics epoch={:?}", epoch);

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Ok(light
                .get_pos_economics(epoch)
                .await
                .map(|ans| PoSEconomics {
                    total_pos_staking_tokens: ans[0],
                    distributable_pos_interest: ans[1],
                    last_distribute_block: ans[2].as_u64().into(),
                })
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?)
        };

        fut.boxed()
    }

    fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> CoreBoxFuture<CheckBalanceAgainstTransactionResponse> {
        let epoch: primitives::EpochNumber =
            epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_checkBalanceAgainstTransaction account_addr={:?} contract_addr={:?} gas_limit={:?} gas_price={:?} storage_limit={:?} epoch={:?}",
            account_addr, contract_addr, gas_limit, gas_price, storage_limit, epoch
        );

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let fut = async move {
            Self::check_address_network(account_addr.network, &light)?;
            Self::check_address_network(contract_addr.network, &light)?;

            let account_addr: H160 = account_addr.into();
            let contract_addr: H160 = contract_addr.into();

            if storage_limit > U256::from(std::u64::MAX) {
                bail!(RpcError::invalid_params(format!("storage_limit has to be within the range of u64 but {} supplied!", storage_limit)));
            }

            // retrieve accounts and sponsor info in parallel
            let (user_account, contract_account, is_sponsored) =
                future::try_join3(
                    light.get_account(epoch.clone(), account_addr),
                    light.get_account(epoch.clone(), contract_addr),
                    light.is_user_sponsored(epoch, contract_addr, account_addr),
                )
                .await?;

            Ok(common::check_balance_against_transaction(
                user_account,
                contract_account,
                is_sponsored,
                gas_limit,
                gas_price,
                storage_limit,
            ))
        };

        fut.boxed()
    }

    fn fee_history(
        &self, mut block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> CoreBoxFuture<CfxFeeHistory> {
        info!(
            "RPC Request: cfx_feeHistory: block_count={}, newest_block={:?}, reward_percentiles={:?}",
            block_count, newest_block, reward_percentiles
        );

        if block_count.as_u64() == 0 {
            return async { Ok(FeeHistory::new().into()) }.boxed();
        }

        if block_count.as_u64() > MAX_FEE_HISTORY_CACHE_BLOCK_COUNT {
            block_count = HexU64::from(MAX_FEE_HISTORY_CACHE_BLOCK_COUNT);
        }

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let light = self.light.clone();
        let reward_percentiles = reward_percentiles.unwrap_or_default();

        let fut = async move {
            let start_height: u64 = light
                .get_height_from_epoch_number(newest_block.into())
                .map_err(|e| e.to_string())
                .map_err(RpcError::invalid_params)?;

            let mut current_height = start_height;

            let mut fee_history = FeeHistory::new();

            while current_height
                >= start_height.saturating_sub(block_count.as_u64() - 1)
            {
                let block = fetch_block_for_fee_history(
                    consensus_graph.clone(),
                    light.clone(),
                    current_height,
                )
                .await?;

                let transactions = block
                    .transactions
                    .iter()
                    .filter(|tx| tx.space() == Space::Native)
                    .map(|x| &**x);
                // Internal error happens only if the fetch header has
                // inconsistent block height
                fee_history
                    .push_front_block(
                        Space::Native,
                        &reward_percentiles,
                        &block.block_header,
                        transactions,
                    )
                    .map_err(|_| RpcError::internal_error())?;

                if current_height == 0 {
                    break;
                } else {
                    current_height -= 1;
                }
            }

            let block = fetch_block_for_fee_history(
                consensus_graph.clone(),
                light.clone(),
                start_height + 1,
            )
            .await?;
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
        };

        fut.boxed()
    }
}

async fn fetch_block_for_fee_history(
    consensus_graph: Arc<
        dyn ConsensusGraphTrait<ConsensusConfig = ConsensusConfig>,
    >,
    light: Arc<QueryService>, height: u64,
) -> cfxcore::errors::Result<primitives::Block> {
    let hash = consensus_graph
        .as_any()
        .downcast_ref::<ConsensusGraph>()
        .expect("downcast should succeed")
        .inner
        .read()
        .get_pivot_hash_from_epoch_number(height)
        .map_err(RpcError::invalid_params)?;

    match light.retrieve_block(hash).await? {
        None => Err(RpcError::internal_error().into()),
        Some(b) => Ok(b),
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
            fn best_block_hash(&self) -> JsonRpcResult<H256>;
            fn confirmation_risk_by_hash(&self, block_hash: H256) -> JsonRpcResult<Option<U256>>;
            fn get_client_version(&self) -> JsonRpcResult<String>;
            fn get_status(&self) -> JsonRpcResult<RpcStatus>;
            fn skipped_blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn account_pending_info(&self, addr: RpcAddress) -> BoxFuture<JsonRpcResult<Option<AccountPendingInfo>>>;
        }

        to self.rpc_impl {
            fn account(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<RpcAccount>>;
            fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn admin(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<Option<RpcAddress>>>;
            fn balance(&self, address: RpcAddress, block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> BoxFuture<JsonRpcResult<Option<RpcBlock>>>;
            fn block_by_hash_with_pivot_assumption(&self, block_hash: H256, pivot_hash: H256, epoch_number: U64) -> BoxFuture<JsonRpcResult<RpcBlock>>;
            fn block_by_hash(&self, hash: H256, include_txs: bool) -> BoxFuture<JsonRpcResult<Option<RpcBlock>>>;
            fn blocks_by_epoch(&self, num: EpochNumber) -> JsonRpcResult<Vec<H256>>;
            fn check_balance_against_transaction(&self, account_addr: RpcAddress, contract_addr: RpcAddress, gas_limit: U256, gas_price: U256, storage_limit: U256, epoch: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<CheckBalanceAgainstTransactionResponse>>;
            fn code(&self, address: RpcAddress, block_hash_or_epoch_num: Option<BlockHashOrEpochNumber>) -> BoxFuture<JsonRpcResult<Bytes>>;
            fn collateral_for_storage(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn deposit_list(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<Vec<DepositInfo>>>;
            fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<U256>;
            fn gas_price(&self) -> BoxFuture<JsonRpcResult<U256>>;
            fn get_logs(&self, filter: CfxRpcLogFilter) -> BoxFuture<JsonRpcResult<Vec<RpcLog>>>;
            fn interest_rate(&self, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn next_nonce(&self, address: RpcAddress, num: Option<BlockHashOrEpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn pos_economics(&self, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<PoSEconomics>>;
            fn send_raw_transaction(&self, raw: Bytes) -> JsonRpcResult<H256>;
            fn sponsor_info(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<SponsorInfo>>;
            fn staking_balance(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<U256>>;
            fn storage_at(&self, addr: RpcAddress, pos: U256, block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>) -> BoxFuture<JsonRpcResult<Option<H256>>>;
            fn storage_root(&self, address: RpcAddress, epoch_num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<Option<StorageRoot>>>;
            fn transaction_by_hash(&self, hash: H256) -> BoxFuture<JsonRpcResult<Option<RpcTransaction>>>;
            fn transaction_receipt(&self, tx_hash: H256) -> BoxFuture<JsonRpcResult<Option<RpcReceipt>>>;
            fn vote_list(&self, address: RpcAddress, num: Option<EpochNumber>) -> BoxFuture<JsonRpcResult<Vec<VoteStakeInfo>>>;
            fn fee_history(&self, block_count: HexU64, newest_block: EpochNumber, reward_percentiles: Option<Vec<f64>>) -> BoxFuture<JsonRpcResult<CfxFeeHistory>>;
        }
    }

    // TODO(thegaram): add support for these
    not_supported! {
        fn account_pending_transactions(&self, address: RpcAddress, maybe_start_nonce: Option<U256>, maybe_limit: Option<U64>) -> BoxFuture<JsonRpcResult<AccountPendingTransactions>>;
        fn block_by_block_number(&self, block_number: U64, include_txs: bool) -> BoxFuture<JsonRpcResult<Option<RpcBlock>>>;
        fn call(&self, request: TransactionRequest, block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>) -> JsonRpcResult<Bytes>;
        fn estimate_gas_and_collateral(&self, request: TransactionRequest, epoch_num: Option<EpochNumber>) -> JsonRpcResult<EstimateGasAndCollateralResponse>;
        fn get_block_reward_info(&self, num: EpochNumber) -> JsonRpcResult<Vec<RpcRewardInfo>>;
        fn get_supply_info(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<TokenSupplyInfo>;
        fn get_collateral_info(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<StorageCollateralInfo>;
        fn get_vote_params(&self, epoch_num: Option<EpochNumber>) -> JsonRpcResult<VoteParamsInfo>;
        fn get_pos_reward_by_epoch(&self, epoch: EpochNumber) -> JsonRpcResult<Option<PoSEpochReward>>;
        fn get_fee_burnt(&self, epoch: Option<EpochNumber>) -> JsonRpcResult<U256>;
        fn max_priority_fee_per_gas(&self) -> BoxFuture<JsonRpcResult<U256>>;
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
            fn add_latency(&self, id: NodeId, latency_ms: f64) -> JsonRpcResult<()>;
            fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> JsonRpcResult<()>;
            fn chain(&self) -> JsonRpcResult<Vec<RpcBlock>>;
            fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> JsonRpcResult<()>;
            fn get_block_count(&self) -> JsonRpcResult<u64>;
            fn get_goodput(&self) -> JsonRpcResult<String>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> JsonRpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> JsonRpcResult<Vec<PeerInfo>>;
            fn save_node_db(&self) -> JsonRpcResult<()>;
            fn say_hello(&self) -> JsonRpcResult<String>;
            fn stop(&self) -> JsonRpcResult<()>;
            fn pos_register(&self, voting_power: U64, version: Option<u8>) -> JsonRpcResult<(Bytes, AccountAddress)>;
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
    }

    not_supported! {
        fn expire_block_gc(&self, timeout: u64) -> JsonRpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> JsonRpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> JsonRpcResult<H256>;
        fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256, timestamp: u64, adaptive: bool) -> JsonRpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>, custom: Option<Vec<Bytes>>) -> JsonRpcResult<H256>;
        fn generate_empty_blocks(&self, num_blocks: usize) -> JsonRpcResult<Vec<H256>>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>) -> JsonRpcResult<H256>;
        fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> JsonRpcResult<H256>;
        fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> JsonRpcResult<H256>;
        fn get_block_status(&self, block_hash: H256) -> JsonRpcResult<(u8, bool)>;
        fn get_executed_info(&self, block_hash: H256) -> JsonRpcResult<(H256, H256)> ;
        fn get_pivot_chain_and_weight(&self, height_range: Option<(u64, u64)>) -> JsonRpcResult<Vec<(H256, U256)>>;
        fn send_usable_genesis_accounts(&self, account_start_index: usize) -> JsonRpcResult<Bytes>;
        fn set_db_crash(&self, crash_probability: f64, crash_exit_code: i32) -> JsonRpcResult<()>;
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
            fn txpool_content(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn txpool_get_account_transactions(&self, address: RpcAddress) -> JsonRpcResult<Vec<RpcTransaction>>;
            fn txpool_clear(&self) -> JsonRpcResult<()>;
            fn accounts(&self) -> JsonRpcResult<Vec<RpcAddress>>;
            fn lock_account(&self, address: RpcAddress) -> JsonRpcResult<bool>;
            fn net_disconnect_node(&self, id: NodeId, op: Option<UpdateNodeOperation>) -> JsonRpcResult<bool>;
            fn net_node(&self, id: NodeId) -> JsonRpcResult<Option<(String, Node)>>;
            fn net_sessions(&self, node_id: Option<NodeId>) -> JsonRpcResult<Vec<SessionDetails>>;
            fn net_throttling(&self) -> JsonRpcResult<throttling::Service>;
            fn new_account(&self, password: String) -> JsonRpcResult<RpcAddress>;
            fn sign(&self, data: Bytes, address: RpcAddress, password: Option<String>) -> JsonRpcResult<H520>;
            fn unlock_account(&self, address: RpcAddress, password: String, duration: Option<U128>) -> JsonRpcResult<bool>;
        }

        to self.rpc_impl {
            fn send_transaction(&self, tx: TransactionRequest, password: Option<String>) -> BoxFuture<JsonRpcResult<H256>>;
        }
    }

    not_supported! {
        fn consensus_graph_state(&self) -> JsonRpcResult<ConsensusGraphStates>;
        fn current_sync_phase(&self) -> JsonRpcResult<String>;
        fn epoch_receipts(&self, epoch: BlockHashOrEpochNumber, include_eth_recepits: Option<bool>) -> JsonRpcResult<Option<Vec<Vec<RpcReceipt>>>>;
        fn epoch_receipt_proof_by_transaction(&self, tx_hash: H256) -> JsonRpcResult<Option<EpochReceiptProof>>;
        fn stat_on_gas_load(&self, epoch: EpochNumber, time_window: U64) -> JsonRpcResult<Option<StatOnGasLoad>>;
        fn sign_transaction(&self, tx: TransactionRequest, password: Option<String>) -> JsonRpcResult<String>;
        fn sync_graph_state(&self) -> JsonRpcResult<SyncGraphStates>;
        fn transactions_by_epoch(&self, epoch_number: U64) -> JsonRpcResult<Vec<WrapTransaction>>;
        fn transactions_by_block(&self, block_hash: H256) -> JsonRpcResult<Vec<WrapTransaction>>;
    }
}
