// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_util_macros::bail;
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::rpc::{
    errors::invalid_params_check,
    helpers::MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
    impls::pos::{convert_to_pos_epoch_reward, hash_value_to_h256},
    types::{
        cfx::check_rpc_address_network, pos::PoSEpochReward,
        AccountPendingInfo, AccountPendingTransactions, Block as RpcBlock,
        BlockHashOrEpochNumber, Bytes, CfxFeeHistory,
        CheckBalanceAgainstTransactionResponse, EpochNumber, FeeHistory,
        RpcAddress, Status as RpcStatus, Transaction as RpcTransaction,
        TxPoolPendingNonceRange, TxPoolStatus, TxWithPoolInfo, U64 as HexU64,
    },
    CoreResult,
};
use log::{debug, info, warn};

use bigdecimal::BigDecimal;
use jsonrpc_core::{
    Error as RpcError, Result as JsonRpcResult, Value as RpcValue,
};
use keccak_hash::keccak;
use num_bigint::{BigInt, ToBigInt};
use parking_lot::{Condvar, Mutex};

use crate::rpc::types::pos::{Block as RpcPosBlock, Decision};
use cfx_addr::Network;
use cfx_parameters::{
    rpc::GAS_PRICE_DEFAULT_VALUE, staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_rpc_utils::error::jsonrpc_error_helpers::internal_rpc_err;
use cfx_types::{
    Address, AddressSpaceUtil, Space, H160, H256, H520, U128, U256, U512, U64,
};
use cfxcore::{
    consensus::pos_handler::PosVerifier, errors::Error as CoreError,
    genesis_block::register_transaction, BlockDataManager, ConsensusGraph,
    ConsensusGraphTrait, PeerInfo, SharedConsensusGraph, SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use diem_crypto::hash::HashValue;
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    block_info::PivotBlockDecision,
    transaction::TransactionPayload,
};
use network::{
    node_table::{Node, NodeEndpoint, NodeEntry, NodeId},
    throttling::{self, THROTTLING_SERVICE},
    NetworkService, SessionDetails, UpdateNodeOperation,
};
use primitives::{Account, Action, Block, SignedTransaction, Transaction};
use storage_interface::DBReaderForPoW;

fn grouped_txs<T, F>(
    txs: Vec<Arc<SignedTransaction>>, converter: F,
) -> BTreeMap<String, BTreeMap<usize, Vec<T>>>
where F: Fn(Arc<SignedTransaction>) -> T {
    let mut addr_grouped_txs: BTreeMap<String, BTreeMap<usize, Vec<T>>> =
        BTreeMap::new();

    for tx in txs {
        let addr = format!("{:?}", tx.sender());
        let addr_entry: &mut BTreeMap<usize, Vec<T>> =
            addr_grouped_txs.entry(addr).or_insert(BTreeMap::new());

        let nonce = tx.nonce().as_usize();
        let nonce_entry: &mut Vec<T> =
            addr_entry.entry(nonce).or_insert(Vec::new());

        nonce_entry.push(converter(tx));
    }

    addr_grouped_txs
}

pub fn check_balance_against_transaction(
    user_account: Option<Account>, contract_account: Option<Account>,
    is_sponsored: bool, gas_limit: U256, gas_price: U256, storage_limit: U256,
) -> CheckBalanceAgainstTransactionResponse {
    let sponsor_for_gas = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_for_gas)
        .unwrap_or_default();

    let gas_bound: U512 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_gas_bound)
        .unwrap_or_default()
        .into();

    let balance_for_gas: U512 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_balance_for_gas)
        .unwrap_or_default()
        .into();

    let sponsor_for_collateral = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_for_collateral)
        .unwrap_or_default();

    let balance_for_collateral: U512 = contract_account
        .as_ref()
        .map(|a| {
            a.sponsor_info.sponsor_balance_for_collateral
                + a.sponsor_info.unused_storage_points()
        })
        .unwrap_or_default()
        .into();

    let user_balance: U512 =
        user_account.map(|a| a.balance).unwrap_or_default().into();

    let gas_cost_in_drip = gas_limit.full_mul(gas_price);

    let will_pay_tx_fee = !is_sponsored
        || sponsor_for_gas.is_zero()
        || (gas_cost_in_drip > gas_bound)
        || (gas_cost_in_drip > balance_for_gas);

    let storage_cost_in_drip =
        storage_limit.full_mul(*DRIPS_PER_STORAGE_COLLATERAL_UNIT);

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

pub struct RpcImpl {
    exit: Arc<(Mutex<bool>, Condvar)>,
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    network: Arc<NetworkService>,
    tx_pool: SharedTransactionPool,
    accounts: Arc<AccountProvider>,
    pub pos_handler: Arc<PosVerifier>,
}

impl RpcImpl {
    pub fn new(
        exit: Arc<(Mutex<bool>, Condvar)>, consensus: SharedConsensusGraph,
        network: Arc<NetworkService>, tx_pool: SharedTransactionPool,
        accounts: Arc<AccountProvider>, pos_verifier: Arc<PosVerifier>,
    ) -> Self {
        let data_man = consensus.get_data_manager().clone();

        RpcImpl {
            exit,
            consensus,
            data_man,
            network,
            tx_pool,
            accounts,
            pos_handler: pos_verifier,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    fn check_address_network(&self, network: Network) -> CoreResult<()> {
        invalid_params_check(
            "address",
            check_rpc_address_network(
                Some(network),
                self.network.get_network_type(),
            ),
        )
        .map_err(|e| e.into())
    }
}

// Cfx RPC implementation
impl RpcImpl {
    pub fn best_block_hash(&self) -> JsonRpcResult<H256> {
        info!("RPC Request: cfx_getBestBlockHash()");
        Ok(self.consensus.best_block_hash().into())
    }

    pub fn gas_price(&self) -> CoreResult<U256> {
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

    pub fn epoch_number(
        &self, epoch_num: Option<EpochNumber>,
    ) -> JsonRpcResult<U256> {
        let consensus_graph = self.consensus_graph();
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber({:?})", epoch_num);
        match consensus_graph.get_height_from_epoch_number(epoch_num.into()) {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    pub fn block_by_epoch_number(
        &self, epoch_num: EpochNumber, include_txs: bool,
    ) -> CoreResult<Option<RpcBlock>> {
        info!("RPC Request: cfx_getBlockByEpochNumber epoch_number={:?} include_txs={:?}", epoch_num, include_txs);
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();

        let epoch_height = consensus_graph
            .get_height_from_epoch_number(epoch_num.into())
            .map_err(RpcError::invalid_params)?;

        let pivot_hash = inner
            .get_pivot_hash_from_epoch_number(epoch_height)
            .map_err(RpcError::invalid_params)?;

        let maybe_block = self
            .data_man
            .block_by_hash(&pivot_hash, false /* update_cache */);
        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(RpcBlock::new(
                &*b,
                *self.network.get_network_type(),
                consensus_graph,
                inner,
                &self.data_man,
                include_txs,
                Some(Space::Native),
            )?)),
        }
    }

    fn primitive_block_by_epoch_number(
        &self, epoch_num: EpochNumber,
    ) -> Option<Arc<Block>> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let epoch_height = consensus_graph
            .get_height_from_epoch_number(epoch_num.into())
            .ok()?;

        let pivot_hash =
            inner.get_pivot_hash_from_epoch_number(epoch_height).ok()?;

        self.data_man
            .block_by_hash(&pivot_hash, false /* update_cache */)
    }

    pub fn get_pos_reward_by_epoch(
        &self, epoch: EpochNumber,
    ) -> JsonRpcResult<Option<PoSEpochReward>> {
        let maybe_block = self.primitive_block_by_epoch_number(epoch);
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
                    .map_err(|_| RpcError::internal_error())?;
                let pos_block = self
                    .pos_handler
                    .pos_ledger_db()
                    .get_committed_block_by_hash(&hash)
                    .map_err(|_| RpcError::internal_error())?;
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
                    *self.network.get_network_type(),
                )
                .map_err(|_| RpcError::internal_error())?;
                Ok(Some(reward_info))
            }
        }
    }

    pub fn confirmation_risk_by_hash(
        &self, block_hash: H256,
    ) -> JsonRpcResult<Option<U256>> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let result = consensus_graph
            .confirmation_meter
            .confirmation_risk_by_hash(inner, block_hash.into());
        if result.is_none() {
            Ok(None)
        } else {
            let risk: BigDecimal = result.unwrap().into();
            let scale = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16).expect("failed to unwrap U256::max into bigInt");

            //TODO: there's a precision problem here, it should be fine under a
            // (2^256 - 1) scale
            let scaled_risk: BigInt = (risk * scale)
                .to_bigint()
                .expect("failed to convert scaled risk to bigInt");
            let (sign, big_endian_bytes) = scaled_risk.to_bytes_be();
            assert_ne!(sign, num_bigint::Sign::Minus);
            let rpc_result = U256::from(big_endian_bytes.as_slice());
            Ok(Some(rpc_result.into()))
        }
    }

    pub fn block_by_hash(
        &self, hash: H256, include_txs: bool,
    ) -> CoreResult<Option<RpcBlock>> {
        let consensus_graph = self.consensus_graph();
        let hash: H256 = hash.into();
        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );

        let inner = &*consensus_graph.inner.read();

        let maybe_block =
            self.data_man.block_by_hash(&hash, false /* update_cache */);

        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(RpcBlock::new(
                &*b,
                *self.network.get_network_type(),
                consensus_graph,
                inner,
                &self.data_man,
                include_txs,
                Some(Space::Native),
            )?)),
        }
    }

    pub fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> CoreResult<RpcBlock> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let block_hash: H256 = block_hash.into();
        let pivot_hash: H256 = pivot_hash.into();
        let epoch_number = epoch_number.as_usize() as u64;

        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        let genesis = self.consensus.get_data_manager().true_genesis.hash();

        // for genesis, check criteria directly
        if block_hash == genesis && (pivot_hash != genesis || epoch_number != 0)
        {
            bail!(RpcError::invalid_params("pivot chain assumption failed"));
        }

        // `block_hash` must match `epoch_number`
        if block_hash != genesis
            && (consensus_graph.get_block_epoch_number(&block_hash)
                != epoch_number.into())
        {
            bail!(RpcError::invalid_params("pivot chain assumption failed"));
        }

        // `pivot_hash` must match `epoch_number`
        inner
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(RpcError::invalid_params)?;

        let block = self
            .data_man
            .block_by_hash(&block_hash, false /* update_cache */)
            .ok_or_else(|| RpcError::invalid_params("Block not found"))?;

        debug!("Build RpcBlock {}", block.hash());
        Ok(RpcBlock::new(
            &*block,
            *self.network.get_network_type(),
            consensus_graph,
            inner,
            &self.data_man,
            true,
            Some(Space::Native),
        )?)
    }

    pub fn block_by_block_number(
        &self, block_number: U64, include_txs: bool,
    ) -> CoreResult<Option<RpcBlock>> {
        let block_number = block_number.as_u64();
        let consensus_graph = self.consensus_graph();

        info!(
            "RPC Request: cfx_getBlockByBlockNumber hash={:?} include_txs={:?}",
            block_number, include_txs
        );

        let inner = &*consensus_graph.inner.read();

        let block_hash = match self
            .data_man
            .hash_by_block_number(block_number, true /* update cache */)
        {
            None => return Ok(None),
            Some(h) => h,
        };

        let maybe_block = self
            .data_man
            .block_by_hash(&block_hash, false /* update_cache */);

        match maybe_block {
            None => Ok(None),
            Some(b) => Ok(Some(RpcBlock::new(
                &*b,
                *self.network.get_network_type(),
                consensus_graph,
                inner,
                &self.data_man,
                include_txs,
                Some(Space::Native),
            )?)),
        }
    }

    pub fn blocks_by_epoch(
        &self, num: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>> {
        info!("RPC Request: cfx_getBlocksByEpoch epoch_number={:?}", num);

        self.consensus
            .get_block_hashes_by_epoch(num.into())
            .map_err(RpcError::invalid_params)
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    pub fn skipped_blocks_by_epoch(
        &self, num: EpochNumber,
    ) -> JsonRpcResult<Vec<H256>> {
        info!(
            "RPC Request: cfx_getSkippedBlocksByEpoch epoch_number={:?}",
            num
        );

        self.consensus
            .get_skipped_block_hashes_by_epoch(num.into())
            .map_err(RpcError::invalid_params)
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    pub fn next_nonce(
        &self, address: RpcAddress, num: Option<BlockHashOrEpochNumber>,
    ) -> CoreResult<U256> {
        self.check_address_network(address.network)?;
        let consensus_graph = self.consensus_graph();

        let num = num.unwrap_or(BlockHashOrEpochNumber::EpochNumber(
            EpochNumber::LatestState,
        ));

        info!(
            "RPC Request: cfx_getNextNonce address={:?} epoch_num={:?}",
            address, num
        );

        // TODO: check if address is not in reserved address space.
        // We pass "num" into next_nonce() function for the error reporting
        // rpc_param_name because the user passed epoch number could be invalid.
        consensus_graph.next_nonce(
            address.hex_address.with_native_space(),
            num.into(),
            "num",
        )
    }

    pub fn fee_history(
        &self, mut block_count: HexU64, newest_block: EpochNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> CoreResult<CfxFeeHistory> {
        if newest_block == EpochNumber::LatestMined {
            return Err(RpcError::invalid_params(
                "newestBlock cannot be 'LatestMined'",
            )
            .into());
        }

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
        // keep read lock to ensure consistent view
        let inner = self.consensus_graph().inner.read();

        let fetch_block = |height| {
            let pivot_hash = inner
                .get_pivot_hash_from_epoch_number(height)
                .map_err(RpcError::invalid_params)?;

            let maybe_block = self
                .data_man
                .block_by_hash(&pivot_hash, false /* update_cache */);
            if let Some(block) = maybe_block {
                // Internal error happens only if the fetch header has
                // inconsistent block height
                Ok(block)
            } else {
                Err(internal_rpc_err("Specified block header does not exist"))
            }
        };

        let start_height: u64 = self
            .consensus_graph()
            .get_height_from_epoch_number(newest_block.into())
            .map_err(RpcError::invalid_params)?;

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

            // Internal error happens only if the fetch header has inconsistent
            // block height
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

        // Fetch the block after the last block in the history
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

    pub fn max_priority_fee_per_gas(&self) -> CoreResult<U256> {
        info!("RPC Request: max_priority_fee_per_gas",);

        let fee_history = self.fee_history(
            HexU64::from(300),
            EpochNumber::LatestState,
            Some(vec![50f64]),
        )?;

        let total_reward: U256 = fee_history
            .reward()
            .iter()
            .map(|x| x.first().unwrap())
            .fold(U256::zero(), |x, y| x + *y);

        Ok(total_reward / 300)
    }
}

// Test RPC implementation
impl RpcImpl {
    pub fn add_latency(
        &self, id: NodeId, latency_ms: f64,
    ) -> JsonRpcResult<()> {
        match self.network.add_latency(id, latency_ms) {
            Ok(_) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn add_peer(
        &self, node_id: NodeId, address: SocketAddr,
    ) -> JsonRpcResult<()> {
        let node = NodeEntry {
            id: node_id,
            endpoint: NodeEndpoint {
                address,
                udp_port: address.port(),
            },
        };
        info!("RPC Request: add_peer({:?})", node.clone());
        match self.network.add_peer(node) {
            Ok(_x) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn chain(&self) -> CoreResult<Vec<RpcBlock>> {
        info!("RPC Request: test_getChain");
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();

        let construct_block = |hash| {
            let block = self
                .data_man
                .block_by_hash(hash, false /* update_cache */)
                .expect("Error to get block by hash");

            RpcBlock::new(
                &*block,
                *self.network.get_network_type(),
                consensus_graph,
                inner,
                &self.data_man,
                true,
                Some(Space::Native),
            )
        };

        Ok(inner
            .all_blocks_with_topo_order()
            .iter()
            .map(construct_block)
            .collect::<Result<_, _>>()?)
    }

    pub fn drop_peer(
        &self, node_id: NodeId, address: SocketAddr,
    ) -> JsonRpcResult<()> {
        let node = NodeEntry {
            id: node_id,
            endpoint: NodeEndpoint {
                address,
                udp_port: address.port(),
            },
        };
        info!("RPC Request: drop_peer({:?})", node.clone());
        match self.network.drop_peer(node) {
            Ok(_) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn get_block_count(&self) -> JsonRpcResult<u64> {
        info!("RPC Request: get_block_count()");
        let count = self.consensus.block_count();
        info!("RPC Response: get_block_count={}", count);
        Ok(count)
    }

    pub fn get_goodput(&self) -> JsonRpcResult<String> {
        let consensus_graph = self.consensus_graph();
        info!("RPC Request: get_goodput");
        let mut all_block_set = HashSet::new();
        for epoch_number in 1..consensus_graph.best_epoch_number() {
            for block_hash in consensus_graph
                .get_block_hashes_by_epoch(epoch_number.into())
                .map_err(|_| RpcError::internal_error())?
            {
                all_block_set.insert(block_hash);
            }
        }
        let mut set = HashSet::new();
        let mut min = std::u64::MAX;
        let mut max: u64 = 0;
        for key in &all_block_set {
            if let Some(block) =
                self.data_man.block_by_hash(key, false /* update_cache */)
            {
                let timestamp = block.block_header.timestamp();
                if timestamp < min && timestamp > 0 {
                    min = timestamp;
                }
                if timestamp > max {
                    max = timestamp;
                }
                for transaction in &block.transactions {
                    set.insert(transaction.hash());
                }
            }
        }
        if max != min {
            //get goodput for the range (30%, 80%)
            let lower_bound = min + ((max - min) as f64 * 0.3) as u64;
            let upper_bound = min + ((max - min) as f64 * 0.8) as u64;
            let mut ranged_set = HashSet::new();
            for key in &all_block_set {
                if let Some(block) = self
                    .data_man
                    .block_by_hash(key, false /* update_cache */)
                {
                    let timestamp = block.block_header.timestamp();
                    if timestamp > lower_bound && timestamp < upper_bound {
                        for transaction in &block.transactions {
                            ranged_set.insert(transaction.hash());
                        }
                    }
                }
            }
            if upper_bound != lower_bound {
                Ok(format!(
                    "full: {}, ranged: {}",
                    set.len() as isize / (max - min) as isize,
                    ranged_set.len() as isize
                        / (upper_bound - lower_bound) as isize
                ))
            } else {
                Ok(format!(
                    "full: {}",
                    set.len() as isize / (max - min) as isize
                ))
            }
        } else {
            Ok("-1".to_string())
        }
    }

    pub fn get_nodeid(&self, challenge: Vec<u8>) -> JsonRpcResult<Vec<u8>> {
        match self.network.sign_challenge(challenge) {
            Ok(r) => Ok(r),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn get_peer_info(&self) -> JsonRpcResult<Vec<PeerInfo>> {
        info!("RPC Request: get_peer_info");
        match self.network.get_peer_info() {
            None => Ok(Vec::new()),
            Some(peers) => Ok(peers),
        }
    }

    pub fn get_status(&self) -> CoreResult<RpcStatus> {
        let consensus_graph = self.consensus_graph();

        let (best_info, block_number) = {
            // keep read lock to maintain consistent view
            let _inner = &*consensus_graph.inner.read();

            let best_info = self.consensus.best_info();

            let block_number = self
                .consensus
                .get_block_number(&best_info.best_block_hash)?
                .ok_or("block_number is missing for best_hash")?
                // The returned block_number of `best_hash` does not include `best_hash` itself.
                + 1;

            (best_info, block_number)
        };

        let tx_count = self.tx_pool.total_unpacked();

        let latest_checkpoint = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestCheckpoint.into())?
            .into();

        let latest_confirmed = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestConfirmed.into())?
            .into();

        let latest_state = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestState.into())?
            .into();

        let latest_finalized = consensus_graph
            .get_height_from_epoch_number(EpochNumber::LatestFinalized.into())?
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
            network_id: self.network.network_id().into(),
            pending_tx_number: tx_count.into(),
        })
    }

    pub fn say_hello(&self) -> JsonRpcResult<String> {
        Ok("Hello, world".into())
    }

    pub fn stop(&self) -> JsonRpcResult<()> {
        *self.exit.0.lock() = true;
        self.exit.1.notify_all();

        Ok(())
    }

    pub fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> JsonRpcResult<(Bytes, AccountAddress)> {
        let legacy = version.map_or(false, |x| x == 0);
        let tx = register_transaction(
            self.pos_handler.config().bls_key.private_key(),
            self.pos_handler.config().vrf_key.public_key(),
            voting_power.as_u64(),
            0,
            legacy,
        );
        let identifier = from_consensus_public_key(
            &self.pos_handler.config().bls_key.public_key(),
            &self.pos_handler.config().vrf_key.public_key(),
        );
        Ok((tx.data.into(), identifier))
    }

    pub fn pos_update_voting_power(
        &self, _pos_account: AccountAddress, _increased_voting_power: U64,
    ) -> JsonRpcResult<()> {
        unimplemented!()
    }

    pub fn pos_stop_election(&self) -> JsonRpcResult<Option<u64>> {
        self.pos_handler.stop_election().map_err(|e| {
            warn!("stop_election: err={:?}", e);
            RpcError::internal_error().into()
        })
    }

    pub fn pos_start_voting(&self, initialize: bool) -> CoreResult<()> {
        info!("RPC Request: pos_start_voting, initialize={}", initialize);
        self.pos_handler.start_voting(initialize).map_err(|e| {
            warn!("start_voting: err={:?}", e);
            CoreError::Custom(e.to_string())
        })
    }

    pub fn pos_stop_voting(&self) -> CoreResult<()> {
        info!("RPC Request: pos_stop_voting");
        self.pos_handler.stop_voting().map_err(|e| {
            warn!("stop_voting: err={:?}", e);
            CoreError::Custom(e.to_string())
        })
    }

    pub fn pos_voting_status(&self) -> CoreResult<bool> {
        self.pos_handler.voting_status().map_err(|e| {
            warn!("voting_status: err={:?}", e);
            CoreError::Custom(e.to_string())
        })
    }

    pub fn pos_start(&self) -> CoreResult<()> {
        self.pos_handler
            .initialize(self.consensus.clone().to_arc_consensus())?;
        Ok(())
    }

    pub fn pos_force_vote_proposal(&self, block_id: H256) -> CoreResult<()> {
        if !self.network.is_test_mode() {
            // Reject force vote if test RPCs are enabled in a mainnet node,
            // because this may cause staked CFXs locked
            // permanently.
            bail!(RpcError::internal_error())
        }
        self.pos_handler.force_vote_proposal(block_id).map_err(|e| {
            warn!("force_vote_proposal: err={:?}", e);
            RpcError::internal_error().into()
        })
    }

    pub fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> CoreResult<()> {
        if !self.network.is_test_mode() {
            // Reject force vote if test RPCs are enabled in a mainnet node,
            // because this may cause staked CFXs locked
            // permanently.
            bail!(RpcError::internal_error())
        }
        self.pos_handler
            .force_propose(round, parent_block_id, payload)
            .map_err(|e| {
                warn!("pos_force_propose: err={:?}", e);
                RpcError::internal_error().into()
            })
    }

    pub fn pos_trigger_timeout(&self, timeout_type: String) -> CoreResult<()> {
        if !self.network.is_test_mode() {
            // Reject force vote if test RPCs are enabled in a mainnet node,
            // because this may cause staked CFXs locked
            // permanently.
            bail!(RpcError::internal_error())
        }
        debug!("pos_trigger_timeout: type={}", timeout_type);
        self.pos_handler.trigger_timeout(timeout_type).map_err(|e| {
            warn!("pos_trigger_timeout: err={:?}", e);
            RpcError::internal_error().into()
        })
    }

    pub fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> CoreResult<()> {
        if !self.network.is_test_mode() {
            // Reject force vote if test RPCs are enabled in a mainnet node,
            // because this may cause staked CFXs locked
            // permanently.
            bail!(RpcError::internal_error())
        }
        self.pos_handler
            .force_sign_pivot_decision(PivotBlockDecision {
                block_hash,
                height: height.as_u64(),
            })
            .map_err(|e| {
                warn!("pos_trigger_timeout: err={:?}", e);
                RpcError::internal_error().into()
            })
    }

    pub fn pos_get_chosen_proposal(&self) -> CoreResult<Option<RpcPosBlock>> {
        let maybe_block = self
            .pos_handler
            .get_chosen_proposal()
            .map_err(|e| {
                warn!("pos_get_chosen_proposal: err={:?}", e);
                RpcError::internal_error()
            })?
            .and_then(|b| {
                let block_hash = b.id();
                self.pos_handler
                    .cached_db()
                    .get_block(&block_hash)
                    .ok()
                    .map(|executed_block| {
                        let executed_block = executed_block.lock();
                        RpcPosBlock {
                            hash: hash_value_to_h256(b.id()),
                            epoch: U64::from(b.epoch()),
                            round: U64::from(b.round()),
                            last_tx_number: executed_block
                                .output()
                                .version()
                                .unwrap_or_default()
                                .into(),
                            miner: b.author().map(|a| H256::from(a.to_u8())),
                            parent_hash: hash_value_to_h256(b.parent_id()),
                            timestamp: U64::from(b.timestamp_usecs()),
                            pivot_decision: executed_block
                                .output()
                                .pivot_block()
                                .as_ref()
                                .map(|d| Decision::from(d)),
                            height: executed_block
                                .output()
                                .executed_trees()
                                .pos_state()
                                .current_view()
                                .into(),
                            signatures: vec![],
                        }
                    })
            });
        Ok(maybe_block)
    }
}

// Debug RPC implementation
impl RpcImpl {
    pub fn txpool_clear(&self) -> JsonRpcResult<()> {
        self.tx_pool.clear_tx_pool();
        Ok(())
    }

    pub fn net_node(
        &self, id: NodeId,
    ) -> JsonRpcResult<Option<(String, Node)>> {
        match self.network.get_node(&id) {
            None => Ok(None),
            Some((trusted, node)) => {
                if trusted {
                    Ok(Some(("trusted".into(), node)))
                } else {
                    Ok(Some(("untrusted".into(), node)))
                }
            }
        }
    }

    pub fn net_disconnect_node(
        &self, id: NodeId, op: Option<UpdateNodeOperation>,
    ) -> JsonRpcResult<bool> {
        Ok(self.network.disconnect_node(&id, op))
    }

    pub fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> JsonRpcResult<Vec<SessionDetails>> {
        match self.network.get_detailed_sessions(node_id) {
            None => Ok(Vec::new()),
            Some(sessions) => Ok(sessions),
        }
    }

    pub fn net_throttling(&self) -> JsonRpcResult<throttling::Service> {
        Ok(THROTTLING_SERVICE.read().clone())
    }

    // MARK: Conflux space rpc supports EVM space transaction
    pub fn txpool_tx_with_pool_info(
        &self, hash: H256,
    ) -> JsonRpcResult<TxWithPoolInfo> {
        let mut ret = TxWithPoolInfo::default();
        let hash: H256 = hash.into();
        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            ret.exist = true;
            if self.tx_pool.check_tx_packed_in_deferred_pool(&hash) {
                ret.packed = true;
            }
            let (local_nonce, local_balance) =
                self.tx_pool.get_local_account_info(&tx.sender());
            let (state_nonce, state_balance) = self
                .tx_pool
                .get_state_account_info(&tx.sender())
                .map_err(|e| {
                    let mut rpc_error = RpcError::internal_error();
                    rpc_error.data = Some(RpcValue::String(format!("{}", e)));
                    rpc_error
                })?;
            let required_storage_collateral =
                if let Transaction::Native(ref tx) = tx.unsigned {
                    U256::from(*tx.storage_limit())
                        * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
                } else {
                    U256::zero()
                };
            let required_balance = tx.value()
                + tx.gas() * tx.gas_price()
                + required_storage_collateral;
            ret.local_balance_enough = local_balance > required_balance;
            ret.state_balance_enough = state_balance > required_balance;
            ret.local_balance = local_balance;
            ret.local_nonce = local_nonce;
            ret.state_balance = state_balance;
            ret.state_nonce = state_nonce;
        }
        Ok(ret)
    }

    pub fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> CoreResult<Vec<RpcTransaction>> {
        self.check_address_network(address.network)?;
        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(Some(Address::from(address).with_native_space()));
        let converter =
            |tx: &Arc<SignedTransaction>| -> Result<RpcTransaction, String> {
                RpcTransaction::from_signed(
                    &tx,
                    None,
                    *self.network.get_network_type(),
                )
            };
        let result = ready_txs
            .iter()
            .map(converter)
            .chain(deferred_txs.iter().map(converter))
            .collect::<Result<_, _>>()?;
        return Ok(result);
    }

    pub fn txpool_transaction_by_address_and_nonce(
        &self, address: RpcAddress, nonce: U256,
    ) -> CoreResult<Option<RpcTransaction>> {
        let tx = self
            .tx_pool
            .get_transaction_by_address2nonce(
                Address::from(address).with_native_space(),
                nonce,
            )
            .map(|tx| {
                RpcTransaction::from_signed(
                    &tx,
                    None,
                    *self.network.get_network_type(),
                )
                .unwrap() // TODO check the unwrap()
            });
        Ok(tx)
    }

    pub fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> CoreResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        let address: Option<H160> = match address {
            None => None,
            Some(addr) => {
                self.check_address_network(addr.network)?;
                Some(addr.into())
            }
        };

        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(address.map(AddressSpaceUtil::with_native_space));
        let converter = |tx: Arc<SignedTransaction>| -> RpcTransaction {
            RpcTransaction::from_signed(&tx, None, *self.network.get_network_type())
                .expect("transaction conversion with correct network id should not fail")
        };

        let mut ret: BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        > = BTreeMap::new();
        ret.insert("ready".into(), grouped_txs(ready_txs, converter));
        ret.insert("deferred".into(), grouped_txs(deferred_txs, converter));

        Ok(ret)
    }

    pub fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> CoreResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        let address: Option<H160> = match address {
            None => None,
            Some(addr) => {
                self.check_address_network(addr.network)?;
                Some(addr.into())
            }
        };

        let (ready_txs, deferred_txs) = self
            .tx_pool
            .content(address.map(AddressSpaceUtil::with_native_space));
        let converter = |tx: Arc<SignedTransaction>| -> String {
            let to = match tx.action() {
                Action::Create => "<Create contract>".into(),
                Action::Call(addr) => format!("{:?}", addr),
            };

            format!(
                "{}: {:?} drip + {:?} gas * {:?} drip",
                to,
                tx.value(),
                tx.gas(),
                tx.gas_price()
            )
        };

        let mut ret: BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<String>>>,
        > = BTreeMap::new();
        ret.insert("ready".into(), grouped_txs(ready_txs, converter));
        ret.insert("deferred".into(), grouped_txs(deferred_txs, converter));

        Ok(ret)
    }

    pub fn txpool_status(&self) -> JsonRpcResult<TxPoolStatus> {
        let (ready_len, deferred_len, received_len, unexecuted_len) =
            self.tx_pool.stats();

        Ok(TxPoolStatus {
            deferred: U64::from(deferred_len),
            ready: U64::from(ready_len),
            received: U64::from(received_len),
            unexecuted: U64::from(unexecuted_len),
        })
    }

    pub fn accounts(&self) -> CoreResult<Vec<RpcAddress>> {
        let accounts: Vec<Address> = self.accounts.accounts().map_err(|e| {
            format!("Could not fetch accounts. With error {:?}", e)
        })?;

        Ok(accounts
            .into_iter()
            .map(|addr| {
                RpcAddress::try_from_h160(
                    addr,
                    *self.network.get_network_type(),
                )
            })
            .collect::<Result<_, _>>()?)
    }

    pub fn new_account(&self, password: String) -> CoreResult<RpcAddress> {
        let address =
            self.accounts.new_account(&password.into()).map_err(|e| {
                format!("Could not create account. With error {:?}", e)
            })?;

        Ok(RpcAddress::try_from_h160(
            address,
            *self.network.get_network_type(),
        )?)
    }

    pub fn unlock_account(
        &self, address: RpcAddress, password: String, duration: Option<U128>,
    ) -> CoreResult<bool> {
        self.check_address_network(address.network)?;
        let account: H160 = address.into();
        let store = self.accounts.clone();

        let duration = match duration {
            None => None,
            Some(duration) => {
                let duration: U128 = duration.into();
                let v = duration.low_u64() as u32;
                if duration != v.into() {
                    bail!(RpcError::invalid_params("invalid duration number",));
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
                bail!(RpcError::internal_error())
            }
        }
    }

    pub fn lock_account(&self, address: RpcAddress) -> CoreResult<bool> {
        self.check_address_network(address.network)?;
        match self.accounts.lock_account(address.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("Unable to lock the account. With error {:?}", err);
                bail!(RpcError::internal_error())
            }
        }
    }

    pub fn sign(
        &self, data: Bytes, address: RpcAddress, password: Option<String>,
    ) -> CoreResult<H520> {
        self.check_address_network(address.network)?;

        let message = eth_data_hash(data.0);
        let password = password.map(Password::from);
        let signature =
            match self.accounts.sign(address.into(), password, message) {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("Unable to sign the message. With error {:?}", err);
                    bail!(RpcError::internal_error());
                }
            };
        Ok(H520(signature.into()))
    }

    pub fn save_node_db(&self) -> JsonRpcResult<()> {
        self.network.save_node_db();
        Ok(())
    }

    pub fn get_client_version(&self) -> JsonRpcResult<String> {
        Ok(parity_version::conflux_client_version!())
    }

    pub fn txpool_pending_nonce_range(
        &self, address: RpcAddress,
    ) -> CoreResult<TxPoolPendingNonceRange> {
        self.check_address_network(address.network)?;

        let mut ret = TxPoolPendingNonceRange::default();
        let (pending_txs, _, _) =
            self.tx_pool.get_account_pending_transactions(
                &address.hex_address.with_native_space(),
                None,
                None,
                self.consensus.best_epoch_number(),
            )?;
        let mut max_nonce: U256 = U256::from(0);
        let mut min_nonce: U256 = U256::max_value();
        for tx in pending_txs.iter() {
            if *tx.nonce() > max_nonce {
                max_nonce = *tx.nonce();
            }
            if *tx.nonce() < min_nonce {
                min_nonce = *tx.nonce();
            }
        }
        ret.min_nonce = min_nonce;
        ret.max_nonce = max_nonce;
        Ok(ret)
    }

    pub fn txpool_next_nonce(&self, address: RpcAddress) -> CoreResult<U256> {
        Ok(self
            .tx_pool
            .get_next_nonce(&address.hex_address.with_native_space()))
    }

    pub fn account_pending_info(
        &self, address: RpcAddress,
    ) -> CoreResult<Option<AccountPendingInfo>> {
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

    pub fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> CoreResult<AccountPendingTransactions> {
        info!("RPC Request: cfx_getAccountPendingTransactions(addr={:?}, start_nonce={:?}, limit={:?})",
              address, maybe_start_nonce, maybe_limit);
        self.check_address_network(address.network)?;

        let (pending_txs, tx_status, pending_count) =
            self.tx_pool.get_account_pending_transactions(
                &Address::from(address).with_native_space(),
                maybe_start_nonce,
                maybe_limit.map(|limit| limit.as_usize()),
                self.consensus.best_epoch_number(),
            )?;
        Ok(AccountPendingTransactions {
            pending_transactions: pending_txs
                .into_iter()
                .map(|tx| {
                    RpcTransaction::from_signed(
                        &tx,
                        None,
                        *self.network.get_network_type(),
                    )
                })
                .collect::<Result<Vec<RpcTransaction>, String>>()?,
            first_tx_status: tx_status,
            pending_count: pending_count.into(),
        })
    }
}

/// Returns a eth_sign-compatible hash of data to sign.
/// The data is prepended with special message to prevent
/// malicious DApps from using the function to sign forged transactions.
fn eth_data_hash(mut data: Vec<u8>) -> H256 {
    let mut message_data =
        format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    message_data.append(&mut data);
    keccak(message_data)
}
