// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use cfx_addr::Network;
use cfx_parameters::rpc::GAS_PRICE_DEFAULT_VALUE;
use cfx_rpc_cfx_api::{
    CfxDebugRpcServer, CfxRpcServer, DebugRpcServer, TestRpcServer,
};
use cfx_rpc_cfx_types::{
    address::check_rpc_address_network,
    pos::{Block as PosBlock, PoSEpochReward},
    receipt::Receipt as RpcReceipt,
    Account as RpcAccount, AccountPendingInfo, AccountPendingTransactions,
    BlameInfo, Block as RpcBlock, Block, BlockHashOrEpochNumber, Bytes,
    Bytes as RpcBytes, CfxFeeHistory, CfxRpcLogFilter,
    CheckBalanceAgainstTransactionResponse, ConsensusGraphStates, EpochNumber,
    EstimateGasAndCollateralResponse, Log as RpcLog, PoSEconomics,
    RewardInfo as RpcRewardInfo, RpcAddress, SponsorInfo, StatOnGasLoad,
    Status as RpcStatus, StorageCollateralInfo, SyncGraphStates,
    TokenSupplyInfo, Transaction as RpcTransaction, TransactionRequest,
    VoteParamsInfo,
};
use cfx_rpc_eth_types::{FeeHistory, WrapTransaction};
use cfx_rpc_primitives::U64 as HexU64;
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    internal_error, invalid_params_check, invalid_params_msg, unimplemented,
};
use cfx_types::{
    AddressSpaceUtil, BigEndianHash, Space, H160, H256, H520, U128, U256, U64,
};
use cfxcore::{
    block_data_manager::BlockDataManager,
    errors::account_result_to_rpc_result,
    light_protocol::{
        query_service::TxInfo, Error as LightError,
        Error as LightProtocolError, QueryService,
    },
    ConsensusGraph, LightQueryService, SharedConsensusGraph,
};
use cfxcore_accounts::AccountProvider;
use diem_types::{
    account_address::AccountAddress, transaction::TransactionPayload,
};
use futures::future;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use log::{debug, info};
use network::{
    node_table::{Node, NodeId},
    throttling, PeerInfo, SessionDetails, UpdateNodeOperation,
};
use primitives::{
    Account, DepositInfo, StorageRoot, TransactionWithSignature, VoteStakeInfo,
};
use rlp::Encodable;

use crate::{
    check_balance_against_transaction,
    common::CommonRpcImpl,
    helpers::{build_block, MAX_FEE_HISTORY_CACHE_BLOCK_COUNT},
};

fn into_rpc_err<E>(e: E) -> ErrorObjectOwned
where cfxcore::errors::Error: From<E> {
    ErrorObjectOwned::from(cfxcore::errors::Error::from(e))
}

fn not_supported() -> ErrorObjectOwned {
    unimplemented(Some("Tracking issue: https://github.com/Conflux-Chain/conflux-rust/issues/1461".into()))
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
    ) -> RpcResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(Some(network), light.get_network_type()),
        )
    }

    fn get_epoch_number_with_pivot_check(
        consensus_graph: SharedConsensusGraph,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<EpochNumber> {
        match block_hash_or_epoch_number {
            Some(BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            }) => {
                let epoch_number = consensus_graph
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

    async fn account(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAccount address={:?} epoch={:?}",
            address, epoch
        );

        Self::check_address_network(address.network, &self.light)?;
        let network = address.network;

        let account = invalid_params_check(
            "epoch",
            self.light.get_account(epoch, address.hex_address).await,
        )?;

        let account = account.unwrap_or(account_result_to_rpc_result(
            "address",
            Ok(Account::new_empty_with_balance(
                &address.hex_address.with_native_space(),
                &U256::zero(), /* balance */
                &U256::zero(), /* nonce */
            )),
        )?);

        Ok(RpcAccount::try_from(account, network).map_err(into_rpc_err)?)
    }

    async fn balance(
        &self, address: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
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
    }

    async fn admin(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcAddress>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();
        let network = address.network;

        info!(
            "RPC Request: cfx_getAdmin address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let account = invalid_params_check(
            "address",
            light.get_account(epoch, address.into()).await,
        )?;

        match account {
            None => Ok(None),
            Some(acc) => Ok(Some(
                RpcAddress::try_from_h160(acc.admin, network)
                    .map_err(into_rpc_err)?,
            )),
        }
    }

    async fn sponsor_info(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<SponsorInfo> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getSponsorInfo address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;
        let network = address.network;

        let account = invalid_params_check(
            "address",
            light.get_account(epoch, address.into()).await,
        )?;

        match account {
            None => Ok(SponsorInfo::default(network).map_err(into_rpc_err)?),
            Some(acc) => Ok(SponsorInfo::try_from(acc.sponsor_info, network)
                .map_err(into_rpc_err)?),
        }
    }

    async fn staking_balance(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getStakingBalance address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let account = invalid_params_check(
            "address",
            light.get_account(epoch, address.into()).await,
        )?;

        Ok(account
            .map(|account| account.staking_balance.into())
            .unwrap_or_default())
    }

    async fn deposit_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Vec<DepositInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getDepositList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let maybe_list = invalid_params_check(
            "address",
            light.get_deposit_list(epoch, address.into()).await,
        )?;

        match maybe_list {
            None => Ok(vec![]),
            Some(deposit_list) => Ok(deposit_list.0),
        }
    }

    pub async fn account_pending_info(
        &self, _address: RpcAddress,
    ) -> RpcResult<Option<AccountPendingInfo>> {
        Ok(None)
    }

    async fn vote_list(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<Vec<VoteStakeInfo>> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getVoteList address={:?} epoch_num={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let maybe_list = invalid_params_check(
            "address",
            light.get_vote_list(epoch, address.into()).await,
        )?;

        match maybe_list {
            None => Ok(vec![]),
            Some(vote_list) => Ok(vote_list.0),
        }
    }

    async fn collateral_for_storage(
        &self, address: RpcAddress, num: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch = num.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getCollateralForStorage address={:?} epoch={:?}",
            address, epoch
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let account = invalid_params_check(
            "address",
            light.get_account(epoch, address.into()).await,
        )?;

        Ok(account
            .map(|account| account.collateral_for_storage.into())
            .unwrap_or_default())
    }

    async fn code(
        &self, address: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Bytes> {
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

        let epoch = Self::get_epoch_number_with_pivot_check(
            consensus_graph,
            block_hash_or_epoch_number,
        )?
        .into();
        Self::check_address_network(address.network, &light)?;

        // FIXME:
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
    }

    async fn get_logs(
        &self, filter: CfxRpcLogFilter,
    ) -> RpcResult<Vec<RpcLog>> {
        info!("RPC Request: cfx_getLogs filter={:?}", filter);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

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
            .map_err(|e| invalid_params_msg(&e))?;

        Ok(logs
            .into_iter()
            .map(|l| RpcLog::try_from_localized(l, *light.get_network_type()))
            .collect::<Result<_, _>>()
            .map_err(into_rpc_err)?)
    }

    fn send_tx_helper(
        light: Arc<LightQueryService>, raw: Bytes,
    ) -> RpcResult<H256> {
        let raw: Vec<u8> = raw.into_vec();

        // decode tx so that we have its hash
        // this way we also avoid spamming peers with invalid txs
        let tx: TransactionWithSignature =
            TransactionWithSignature::from_raw(&raw)
                .map_err(|e| format!("Failed to decode tx: {:?}", e))
                .map_err(|e| invalid_params_msg(&e))?;

        debug!("Deserialized tx: {:?}", tx);

        // TODO(thegaram): consider adding a light node specific tx pool;
        // light nodes would track those txs and maintain their statuses
        // for future queries

        match /* success = */ light.send_raw_tx(raw) {
            true => Ok(tx.hash().into()),
            false => Err(into_rpc_err(LightProtocolError::InternalError("Unable to relay tx".into()))),
        }
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);
        Self::send_tx_helper(self.light.clone(), raw)
    }

    async fn send_transaction(
        &self, mut tx: TransactionRequest, password: Option<String>,
    ) -> RpcResult<H256> {
        info!("RPC Request: cfx_sendTransaction tx={:?}", tx);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let accounts = self.accounts.clone();

        tx.check_rpc_address_network("tx", light.get_network_type())?;

        if tx.nonce.is_none() {
            // TODO(thegaram): consider adding a light node specific tx pool
            // to track the nonce

            let address = tx
                .from
                .clone()
                .ok_or("from should exist")
                .map_err(into_rpc_err)?
                .into();
            let epoch = EpochNumber::LatestState.into_primitive();

            let nonce = light
                .get_account(epoch, address)
                .await
                .map_err(into_rpc_err)?
                .map(|a| a.nonce)
                .unwrap_or(U256::zero());

            tx.nonce.replace(nonce.into());
            debug!("after loading nonce in latest state, tx = {:?}", tx);
        }

        let epoch_height = light.get_latest_verifiable_epoch_number().map_err(|_| {
            format!("the light client cannot retrieve/verify the latest mined pivot block.")
        }).map_err(into_rpc_err)?;
        let chain_id = light.get_latest_verifiable_chain_id().map_err(|_| {
            format!("the light client cannot retrieve/verify the latest chain_id.")
        }).map_err(into_rpc_err)?;
        let tx = tx
            .sign_with(
                epoch_height,
                chain_id.in_native_space(),
                password,
                accounts,
            )
            .map_err(into_rpc_err)?;

        Self::send_tx_helper(light, Bytes::new(tx.rlp_bytes().to_vec()))
    }

    async fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<StorageRoot>> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestState);

        info!(
            "RPC Request: cfx_getStorageRoot address={:?} epoch={:?})",
            address, epoch_num
        );

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(address.network, &light)?;

        let root = invalid_params_check(
            "address",
            light
                .get_storage_root(epoch_num.into(), address.into())
                .await,
        )?;

        Ok(Some(root))
    }

    async fn storage_at(
        &self, address: RpcAddress, position: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Option<H256>> {
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

        let epoch_num = Self::get_epoch_number_with_pivot_check(
            consensus_graph,
            block_hash_or_epoch_number,
        )?;
        Self::check_address_network(address.network, &light)?;

        let maybe_entry = light
            .get_storage(epoch_num.into(), address.into(), position)
            .await
            .map_err(into_rpc_err)?;

        Ok(maybe_entry.map(Into::into))
    }

    async fn transaction_by_hash(
        &self, hash: H256,
    ) -> RpcResult<Option<RpcTransaction>> {
        info!("RPC Request: cfx_getTransactionByHash hash={:?}", hash);

        // TODO(thegaram): try to retrieve from local tx pool or cache first

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        let tx = light.get_tx(hash.into()).await.map_err(into_rpc_err)?;

        Ok(Some(
            RpcTransaction::from_signed(&tx, None, *light.get_network_type())
                .map_err(into_rpc_err)?,
        ))
    }

    async fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let hash: H256 = tx_hash.into();
        info!("RPC Request: cfx_getTransactionReceipt hash={:?}", hash);

        // clone `self.light` to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();
        let data_man = self.data_man.clone();

        // TODO:
        //  return an RpcReceipt directly after splitting cfxcore into
        //  smaller crates. It's impossible now because of circular
        //  dependency.

        // return `null` on timeout
        let tx_info = match light.get_tx_info(hash).await {
            Ok(t) => t,
            Err(LightError::Timeout(_)) => return Ok(None),
            Err(e) => {
                return Err(invalid_params_msg(&e.to_string()));
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
            maybe_base_price,
            maybe_state_root,
            // Can not offer error_message from light node.
            None,
            *light.get_network_type(),
            false,
            true,
        )
        .map_err(into_rpc_err)?;

        Ok(Some(receipt))
    }

    pub fn epoch_number(&self, epoch: Option<EpochNumber>) -> RpcResult<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber epoch={:?}", epoch);

        invalid_params_check(
            "epoch",
            self.light
                .get_height_from_epoch_number(epoch.into())
                .map(|height| height.into()),
        )
    }

    pub async fn next_nonce(
        &self, address: RpcAddress, num: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        info!(
            "RPC Request: cfx_getNextNonce address={:?} num={:?}",
            address, num
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let light = self.light.clone();

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
    }

    pub async fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let hash = hash.into();

        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let data_man = self.data_man.clone();
        let light = self.light.clone();

        let block =
            match light.retrieve_block(hash).await.map_err(into_rpc_err)? {
                None => return Ok(None),
                Some(b) => b,
            };

        let inner = consensus_graph.inner.read();

        Ok(Some(
            build_block(
                &block,
                *light.get_network_type(),
                &*consensus_graph,
                &*inner,
                &data_man,
                include_txs,
                Some(Space::Native),
            )
            .map_err(into_rpc_err)?,
        ))
    }

    pub async fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> RpcResult<RpcBlock> {
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

        // check pivot assumption
        // make sure not to hold the lock through await's
        consensus_graph
            .inner
            .read()
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        // retrieve block body
        let block = light
            .retrieve_block(block_hash)
            .await
            .map_err(into_rpc_err)?
            .ok_or_else(|| invalid_params_msg("Block not found"))?;

        let inner = consensus_graph.inner.read();

        Ok(build_block(
            &block,
            *light.get_network_type(),
            &*consensus_graph,
            &*inner,
            &data_man,
            true,
            Some(Space::Native),
        )
        .map_err(into_rpc_err)?)
    }

    pub async fn block_by_epoch_number(
        &self, epoch: EpochNumber, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        info!(
            "RPC Request: cfx_getBlockByEpochNumber epoch={:?} include_txs={:?}",
            epoch, include_txs
        );

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let data_man = self.data_man.clone();
        let light = self.light.clone();

        let epoch: u64 = light
            .get_height_from_epoch_number(epoch.into())
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        // make sure not to hold the lock through await's
        let hash = consensus_graph
            .inner
            .read()
            .get_pivot_hash_from_epoch_number(epoch)
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        // retrieve block body
        let block =
            match light.retrieve_block(hash).await.map_err(into_rpc_err)? {
                None => return Ok(None),
                Some(b) => b,
            };

        let inner = consensus_graph.inner.read();

        Ok(Some(
            build_block(
                &block,
                *light.get_network_type(),
                &*consensus_graph,
                &*inner,
                &data_man,
                include_txs,
                Some(Space::Native),
            )
            .map_err(into_rpc_err)?,
        ))
    }

    pub fn blocks_by_epoch(&self, epoch: EpochNumber) -> RpcResult<Vec<H256>> {
        info!("RPC Request: cfx_getBlocksByEpoch epoch_number={:?}", epoch);

        let height = self
            .light
            .get_height_from_epoch_number(epoch.into())
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        let hashes = self
            .consensus
            .inner
            .read()
            .block_hashes_by_epoch(height)
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

        Ok(hashes)
    }

    pub async fn gas_price(&self) -> RpcResult<U256> {
        info!("RPC Request: cfx_gasPrice");

        let light = self.light.clone();

        Ok(light
            .gas_price()
            .await
            .map_err(|e| invalid_params_msg(&e.to_string()))?
            .unwrap_or(GAS_PRICE_DEFAULT_VALUE.into()))
    }

    pub async fn interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();
        info!("RPC Request: cfx_getInterestRate epoch={:?}", epoch);

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Ok(light
            .get_interest_rate(epoch)
            .await
            .map_err(|e| invalid_params_msg(&e.to_string()))?)
    }

    pub async fn accumulate_interest_rate(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_getAccumulateInterestRate epoch={:?}",
            epoch
        );

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Ok(light
            .get_accumulate_interest_rate(epoch)
            .await
            .map_err(|e| invalid_params_msg(&e.to_string()))?)
    }

    pub async fn pos_economics(
        &self, epoch: Option<EpochNumber>,
    ) -> RpcResult<PoSEconomics> {
        let epoch = epoch.unwrap_or(EpochNumber::LatestState).into();

        info!("RPC Request: cfx_getPoSEconomics epoch={:?}", epoch);

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Ok(light
            .get_pos_economics(epoch)
            .await
            .map(|ans| PoSEconomics {
                total_pos_staking_tokens: ans[0],
                distributable_pos_interest: ans[1],
                last_distribute_block: ans[2].as_u64().into(),
            })
            .map_err(|e| invalid_params_msg(&e.to_string()))?)
    }

    async fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> RpcResult<CheckBalanceAgainstTransactionResponse> {
        let epoch: primitives::EpochNumber =
            epoch.unwrap_or(EpochNumber::LatestState).into();

        info!(
            "RPC Request: cfx_checkBalanceAgainstTransaction account_addr={:?} contract_addr={:?} gas_limit={:?} gas_price={:?} storage_limit={:?} epoch={:?}",
            account_addr, contract_addr, gas_limit, gas_price, storage_limit, epoch
        );

        // clone to avoid lifetime issues due to capturing `self`
        let light = self.light.clone();

        Self::check_address_network(account_addr.network, &light)?;
        Self::check_address_network(contract_addr.network, &light)?;

        let account_addr: H160 = account_addr.into();
        let contract_addr: H160 = contract_addr.into();

        if storage_limit > U256::from(std::u64::MAX) {
            return Err(invalid_params_msg(&format!("storage_limit has to be within the range of u64 but {} supplied!", storage_limit)));
        }

        // retrieve accounts and sponsor info in parallel
        let (user_account, contract_account, is_sponsored) = future::try_join3(
            light.get_account(epoch.clone(), account_addr),
            light.get_account(epoch.clone(), contract_addr),
            light.is_user_sponsored(epoch, contract_addr, account_addr),
        )
        .await
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

    async fn fee_history(
        &self, mut block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<CfxFeeHistory> {
        info!(
            "RPC Request: cfx_feeHistory: block_count={}, newest_block={:?}, reward_percentiles={:?}",
            block_count, newest_block, reward_percentiles
        );

        if block_count.as_u64() == 0 {
            return Ok(FeeHistory::new().into());
        }

        if block_count.as_u64() > MAX_FEE_HISTORY_CACHE_BLOCK_COUNT {
            block_count = HexU64::from(MAX_FEE_HISTORY_CACHE_BLOCK_COUNT);
        }

        // clone to avoid lifetime issues due to capturing `self`
        let consensus_graph = self.consensus.clone();
        let light = self.light.clone();
        let reward_percentiles = reward_percentiles.unwrap_or_default();

        let start_height: u64 = light
            .get_height_from_epoch_number(newest_block.into())
            .map_err(|e| invalid_params_msg(&e.to_string()))?;

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
                .map_err(|_| internal_error())?;

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
    }
}

async fn fetch_block_for_fee_history(
    consensus_graph: Arc<ConsensusGraph>, light: Arc<QueryService>, height: u64,
) -> RpcResult<primitives::Block> {
    let hash = consensus_graph
        .inner
        .read()
        .get_pivot_hash_from_epoch_number(height)
        .map_err(|e| invalid_params_msg(&e.to_string()))?;

    match light.retrieve_block(hash).await.map_err(into_rpc_err)? {
        None => Err(internal_error()),
        Some(b) => Ok(b),
    }
}

pub struct LightCfxHandler {
    rpc_impl: Arc<RpcImpl>,
    common_impl: Arc<CommonRpcImpl>,
}

impl LightCfxHandler {
    pub fn new(
        rpc_impl: Arc<RpcImpl>, common_impl: Arc<CommonRpcImpl>,
    ) -> Self {
        LightCfxHandler {
            rpc_impl,
            common_impl,
        }
    }
}

#[async_trait::async_trait]
impl CfxRpcServer for LightCfxHandler {
    /// Returns current gas price.
    async fn gas_price(&self) -> RpcResult<U256> {
        self.rpc_impl.gas_price().await
    }

    /// Returns current max_priority_fee
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        return Err(not_supported());
    }

    /// Returns highest epoch number.
    async fn epoch_number(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl.epoch_number(epoch_number)
    }

    /// Returns balance of the given account.
    async fn balance(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl
            .balance(addr, block_hash_or_epoch_number)
            .await
    }

    /// Returns admin of the given contract
    async fn admin(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Option<RpcAddress>> {
        self.rpc_impl.admin(addr, epoch_number).await
    }

    /// Returns sponsor information of the given contract
    async fn sponsor_info(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<SponsorInfo> {
        self.rpc_impl.sponsor_info(addr, epoch_number).await
    }

    /// Returns balance of the given account.
    async fn staking_balance(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl.staking_balance(addr, epoch_number).await
    }

    /// Returns deposit list of the given account.
    async fn deposit_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Vec<DepositInfo>> {
        self.rpc_impl.deposit_list(addr, epoch_number).await
    }

    /// Returns vote list of the given account.
    async fn vote_list(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Vec<VoteStakeInfo>> {
        self.rpc_impl.vote_list(addr, epoch_number).await
    }

    /// Returns balance of the given account.
    async fn collateral_for_storage(
        &self, addr: RpcAddress, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl
            .collateral_for_storage(addr, epoch_number)
            .await
    }

    /// Returns the code at given address at given time (epoch number).
    async fn code(
        &self, addr: RpcAddress,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Bytes> {
        self.rpc_impl.code(addr, block_hash_or_epoch_number).await
    }

    /// Returns storage entries from a given contract.
    async fn storage_at(
        &self, addr: RpcAddress, pos: U256,
        block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Option<H256>> {
        self.rpc_impl
            .storage_at(addr, pos, block_hash_or_epoch_number)
            .await
    }

    async fn storage_root(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<Option<StorageRoot>> {
        self.rpc_impl.storage_root(address, epoch_num).await
    }

    /// Returns block with given hash.
    async fn block_by_hash(
        &self, block_hash: H256, include_txs: bool,
    ) -> RpcResult<Option<Block>> {
        self.rpc_impl.block_by_hash(block_hash, include_txs).await
    }

    /// Returns block with given hash and pivot chain assumption.
    async fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> RpcResult<Block> {
        self.rpc_impl
            .block_by_hash_with_pivot_assumption(
                block_hash,
                pivot_hash,
                epoch_number,
            )
            .await
    }

    /// Returns block with given epoch number.
    async fn block_by_epoch_number(
        &self, epoch_number: EpochNumber, include_txs: bool,
    ) -> RpcResult<Option<Block>> {
        self.rpc_impl
            .block_by_epoch_number(epoch_number, include_txs)
            .await
    }

    /// Returns best block hash.
    async fn best_block_hash(&self) -> RpcResult<H256> {
        self.common_impl.best_block_hash()
    }

    /// Returns the nonce should be filled in next sending transaction from
    /// given address at given time (epoch number).
    async fn next_nonce(
        &self, addr: RpcAddress, epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl.next_nonce(addr, epoch_number).await
    }

    /// Sends signed transaction, returning its hash.
    async fn send_raw_transaction(&self, raw_tx: Bytes) -> RpcResult<H256> {
        self.rpc_impl.send_raw_transaction(raw_tx)
    }

    /// Call contract, returning the output data.
    async fn call(
        &self, _tx: TransactionRequest,
        _block_hash_or_epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<Bytes> {
        return Err(not_supported());
    }

    /// Returns logs matching the filter provided.
    async fn get_logs(
        &self, filter: CfxRpcLogFilter,
    ) -> RpcResult<Vec<RpcLog>> {
        self.rpc_impl.get_logs(filter).await
    }

    /// Get transaction by its hash.
    async fn transaction_by_hash(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcTransaction>> {
        self.rpc_impl.transaction_by_hash(tx_hash).await
    }

    /// Return estimated gas and collateral usage.
    async fn estimate_gas_and_collateral(
        &self, _request: TransactionRequest, _epoch_number: Option<EpochNumber>,
    ) -> RpcResult<EstimateGasAndCollateralResponse> {
        return Err(not_supported());
    }

    async fn fee_history(
        &self, block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<CfxFeeHistory> {
        self.rpc_impl
            .fee_history(block_count, newest_block, reward_percentiles)
            .await
    }

    /// Check if user balance is enough for the transaction.
    async fn check_balance_against_transaction(
        &self, account_addr: RpcAddress, contract_addr: RpcAddress,
        gas_limit: U256, gas_price: U256, storage_limit: U256,
        epoch: Option<EpochNumber>,
    ) -> RpcResult<CheckBalanceAgainstTransactionResponse> {
        self.rpc_impl
            .check_balance_against_transaction(
                account_addr,
                contract_addr,
                gas_limit,
                gas_price,
                storage_limit,
                epoch,
            )
            .await
    }

    async fn blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<Vec<H256>> {
        self.rpc_impl.blocks_by_epoch(epoch_number)
    }

    async fn skipped_blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<Vec<H256>> {
        self.common_impl.skipped_blocks_by_epoch(epoch_number)
    }

    async fn transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        self.rpc_impl.transaction_receipt(tx_hash).await
    }

    /// Return account related states of the given account
    async fn account(
        &self, address: RpcAddress, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcAccount> {
        self.rpc_impl.account(address, epoch_num).await
    }

    /// Returns interest rate of the given epoch
    async fn interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl.interest_rate(epoch_number).await
    }

    /// Returns accumulate interest rate of the given epoch
    async fn accumulate_interest_rate(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        self.rpc_impl.accumulate_interest_rate(epoch_number).await
    }

    /// Returns accumulate interest rate of the given epoch
    async fn pos_economics(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<PoSEconomics> {
        self.rpc_impl.pos_economics(epoch_number).await
    }

    async fn confirmation_risk_by_hash(
        &self, block_hash: H256,
    ) -> RpcResult<Option<U256>> {
        self.common_impl.confirmation_risk_by_hash(block_hash)
    }

    async fn get_status(&self) -> RpcResult<RpcStatus> {
        self.common_impl.get_status()
    }

    /// Return the client version as a string
    async fn get_client_version(&self) -> RpcResult<String> {
        self.common_impl.get_client_version()
    }

    /// Return information about total token supply.
    async fn get_supply_info(
        &self, _epoch_number: Option<EpochNumber>,
    ) -> RpcResult<TokenSupplyInfo> {
        return Err(not_supported());
    }

    /// Returns block reward information in an epoch
    async fn get_block_reward_info(
        &self, _num: EpochNumber,
    ) -> RpcResult<Vec<RpcRewardInfo>> {
        return Err(not_supported());
    }

    /// Return information about total token supply.
    async fn get_collateral_info(
        &self, _epoch_number: Option<EpochNumber>,
    ) -> RpcResult<StorageCollateralInfo> {
        return Err(not_supported());
    }

    async fn get_fee_burnt(
        &self, _epoch_number: Option<EpochNumber>,
    ) -> RpcResult<U256> {
        return Err(not_supported());
    }

    async fn get_pos_reward_by_epoch(
        &self, _epoch: EpochNumber,
    ) -> RpcResult<Option<PoSEpochReward>> {
        return Err(not_supported());
    }

    async fn get_vote_params(
        &self, _epoch_number: Option<EpochNumber>,
    ) -> RpcResult<VoteParamsInfo> {
        return Err(not_supported());
    }

    /// Returns block with given block number.
    async fn block_by_block_number(
        &self, _block_number: U64, _include_txs: bool,
    ) -> RpcResult<Option<Block>> {
        return Err(not_supported());
    }
}

#[async_trait::async_trait]
impl CfxDebugRpcServer for LightCfxHandler {
    async fn send_transaction(
        &self, tx: TransactionRequest, password: Option<String>,
    ) -> RpcResult<H256> {
        self.rpc_impl.send_transaction(tx, password).await
    }

    /// Returns accounts list.
    async fn accounts(&self) -> RpcResult<Vec<RpcAddress>> {
        self.common_impl.accounts()
    }

    /// Create a new account
    async fn new_account(&self, password: String) -> RpcResult<RpcAddress> {
        self.common_impl.new_account(password)
    }

    /// Unlock an account
    async fn unlock_account(
        &self, address: RpcAddress, password: String, duration: Option<U128>,
    ) -> RpcResult<bool> {
        self.common_impl.unlock_account(address, password, duration)
    }

    /// Lock an account
    async fn lock_account(&self, address: RpcAddress) -> RpcResult<bool> {
        self.common_impl.lock_account(address)
    }

    fn sign(
        &self, data: RpcBytes, address: RpcAddress, password: Option<String>,
    ) -> RpcResult<H520> {
        self.common_impl.sign(data, address, password)
    }

    /// Get transaction pending info by account address
    async fn account_pending_info(
        &self, address: RpcAddress,
    ) -> RpcResult<Option<AccountPendingInfo>> {
        self.common_impl.account_pending_info(address)
    }

    fn sign_transaction(
        &self, _tx: TransactionRequest, _password: Option<String>,
    ) -> RpcResult<String> {
        return Err(not_supported());
    }

    async fn epoch_receipts(
        &self, _epoch: BlockHashOrEpochNumber,
        _include_eth_receipts: Option<bool>,
    ) -> RpcResult<Option<Vec<Vec<RpcReceipt>>>> {
        return Err(not_supported());
    }

    /// Get transaction pending info by account address
    async fn account_pending_transactions(
        &self, _address: RpcAddress, _maybe_start_nonce: Option<U256>,
        _maybe_limit: Option<U64>,
    ) -> RpcResult<AccountPendingTransactions> {
        return Err(not_supported());
    }
}

pub struct LightTestHandler {
    test_impl: Arc<CommonRpcImpl>,
}

impl LightTestHandler {
    pub fn new(test_handler: Arc<CommonRpcImpl>) -> Self {
        LightTestHandler {
            test_impl: test_handler,
        }
    }
}

#[async_trait::async_trait]
impl TestRpcServer for LightTestHandler {
    fn say_hello(&self) -> RpcResult<String> { self.test_impl.say_hello() }

    fn get_block_count(&self) -> RpcResult<u64> {
        self.test_impl.get_block_count()
    }

    fn get_goodput(&self) -> RpcResult<String> { self.test_impl.get_goodput() }

    fn generate_empty_blocks(
        &self, _num_blocks: usize,
    ) -> RpcResult<Vec<H256>> {
        return Err(not_supported());
    }

    fn generate_fixed_block(
        &self, _parent: H256, _referee: Vec<H256>, _num_txs: usize,
        _adaptive: bool, _difficulty: Option<u64>,
        _pos_reference: Option<H256>,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn add_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()> {
        self.test_impl.add_peer(id, addr)
    }

    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()> {
        self.test_impl.drop_peer(id, addr)
    }

    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        self.test_impl.get_peer_info()
    }

    /// Returns the JSON of whole chain
    fn chain(&self) -> RpcResult<Vec<Block>> { self.test_impl.chain() }

    fn stop(&self) -> RpcResult<()> { self.test_impl.stop() }

    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        self.test_impl.get_nodeid(challenge)
    }

    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        self.test_impl.add_latency(id, latency_ms)
    }

    fn generate_one_block(
        &self, _num_txs: usize, _block_size_limit: usize,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn generate_one_block_with_direct_txgen(
        &self, _num_txs: usize, _block_size_limit: usize,
        _num_txs_simple: usize, _num_txs_erc20: usize,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn generate_custom_block(
        &self, _parent: H256, _referees: Vec<H256>, _raw: Bytes,
        _adaptive: Option<bool>, _custom: Option<Vec<Bytes>>,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn generate_block_with_fake_txs(
        &self, _raw: Bytes, _adaptive: Option<bool>,
        _tx_data_len: Option<usize>,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn generate_block_with_blame_info(
        &self, _num_txs: usize, _block_size_limit: usize,
        _blame_info: BlameInfo,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn generate_block_with_nonce_and_timestamp(
        &self, _parent: H256, _referees: Vec<H256>, _raw: Bytes, _nonce: U256,
        _timestamp: u64, _adaptive: bool,
    ) -> RpcResult<H256> {
        return Err(not_supported());
    }

    fn get_block_status(&self, _block_hash: H256) -> RpcResult<(u8, bool)> {
        return Err(not_supported());
    }

    fn expire_block_gc(&self, _timeout: u64) -> RpcResult<()> {
        return Err(not_supported());
    }

    fn get_pivot_chain_and_weight(
        &self, _height_range: Option<(u64, u64)>,
    ) -> RpcResult<Vec<(H256, U256)>> {
        return Err(not_supported());
    }

    fn get_executed_info(&self, _block_hash: H256) -> RpcResult<(H256, H256)> {
        return Err(not_supported());
    }

    fn send_usable_genesis_accounts(
        &self, _account_start_index: usize,
    ) -> RpcResult<Bytes> {
        return Err(not_supported());
    }

    fn set_db_crash(
        &self, _crash_probability: f64, _crash_exit_code: i32,
    ) -> RpcResult<()> {
        return Err(not_supported());
    }

    fn save_node_db(&self) -> RpcResult<()> { return Err(not_supported()); }

    fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> RpcResult<(Bytes, AccountAddress)> {
        self.test_impl.pos_register(voting_power, version)
    }

    fn pos_update_voting_power(
        &self, pos_account: AccountAddress, increased_voting_power: U64,
    ) -> RpcResult<()> {
        self.test_impl
            .pos_update_voting_power(pos_account, increased_voting_power)
    }

    fn pos_stop_election(&self) -> RpcResult<Option<u64>> {
        self.test_impl.pos_stop_election()
    }

    fn pos_start_voting(&self, initialize: bool) -> RpcResult<()> {
        self.test_impl.pos_start_voting(initialize)
    }

    fn pos_stop_voting(&self) -> RpcResult<()> {
        self.test_impl.pos_stop_voting()
    }

    fn pos_voting_status(&self) -> RpcResult<bool> {
        self.test_impl.pos_voting_status()
    }

    fn pos_start(&self) -> RpcResult<()> { self.test_impl.pos_start() }

    fn pos_force_vote_proposal(&self, block_id: H256) -> RpcResult<()> {
        self.test_impl.pos_force_vote_proposal(block_id)
    }

    fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> RpcResult<()> {
        self.test_impl
            .pos_force_propose(round, parent_block_id, payload)
    }

    fn pos_trigger_timeout(&self, timeout_type: String) -> RpcResult<()> {
        self.test_impl.pos_trigger_timeout(timeout_type)
    }

    fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> RpcResult<()> {
        self.test_impl
            .pos_force_sign_pivot_decision(block_hash, height)
    }

    fn pos_get_chosen_proposal(&self) -> RpcResult<Option<PosBlock>> {
        self.test_impl.pos_get_chosen_proposal()
    }
}

pub struct LightDebugHandler {
    debug_impl: Arc<CommonRpcImpl>,
}

impl LightDebugHandler {
    pub fn new(debug_impl: Arc<CommonRpcImpl>) -> Self {
        LightDebugHandler { debug_impl }
    }
}

#[async_trait::async_trait]
impl DebugRpcServer for LightDebugHandler {
    fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        self.debug_impl.txpool_inspect(address)
    }

    // return all txpool transactions grouped by hex address
    fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        self.debug_impl.txpool_content(address)
    }

    // return account ready + deferred transactions
    fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> RpcResult<Vec<RpcTransaction>> {
        self.debug_impl.txpool_get_account_transactions(address)
    }

    fn txpool_clear(&self) -> RpcResult<()> { self.debug_impl.txpool_clear() }

    fn net_throttling(&self) -> RpcResult<throttling::Service> {
        self.debug_impl.net_throttling()
    }

    fn net_node(&self, node_id: NodeId) -> RpcResult<Option<(String, Node)>> {
        self.debug_impl.net_node(node_id)
    }

    fn net_disconnect_node(
        &self, id: NodeId, op: Option<UpdateNodeOperation>,
    ) -> RpcResult<bool> {
        self.debug_impl.net_disconnect_node(id, op)
    }

    fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>> {
        self.debug_impl.net_sessions(node_id)
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        return Err(not_supported());
    }

    fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates> {
        return Err(not_supported());
    }

    fn sync_graph_state(&self) -> RpcResult<SyncGraphStates> {
        return Err(not_supported());
    }

    fn stat_on_gas_load(
        &self, _last_epoch: EpochNumber, _time_window: U64,
    ) -> RpcResult<Option<StatOnGasLoad>> {
        return Err(not_supported());
    }

    // #[method(name = "getEpochReceiptProofByTransaction")]
    // fn epoch_receipt_proof_by_transaction(
    //     &self, tx_hash: H256,
    // ) -> RpcResult<Option<EpochReceiptProof>>;

    fn transactions_by_epoch(
        &self, _epoch_number: U64,
    ) -> RpcResult<Vec<WrapTransaction>> {
        return Err(not_supported());
    }

    fn transactions_by_block(
        &self, _block_hash: H256,
    ) -> RpcResult<Vec<WrapTransaction>> {
        return Err(not_supported());
    }
}
