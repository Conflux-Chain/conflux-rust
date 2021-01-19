// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    types::{
        Address as Base32Address, Block as RpcBlock, BlockHashOrEpochNumber,
        Bytes, CheckBalanceAgainstTransactionResponse, EpochNumber,
        Status as RpcStatus, Transaction as RpcTransaction, TxPoolPendingInfo,
        TxWithPoolInfo,
    },
    RpcResult,
};
use bigdecimal::BigDecimal;
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP, staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_types::{Address, H160, H256, H520, U128, U256, U512, U64};
use cfxcore::{
    BlockDataManager, ConsensusGraph, ConsensusGraphTrait, PeerInfo,
    SharedConsensusGraph, SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use cfxkey::Password;
use clap::crate_version;
use jsonrpc_core::{
    Error as RpcError, Result as JsonRpcResult, Value as RpcValue,
};
use keccak_hash::keccak;
use network::{
    node_table::{Node, NodeEndpoint, NodeEntry, NodeId},
    throttling::{self, THROTTLING_SERVICE},
    NetworkService, SessionDetails, UpdateNodeOperation,
};
use num_bigint::{BigInt, ToBigInt};
use parking_lot::{Condvar, Mutex};
use primitives::{Account, Action, SignedTransaction};
use std::{
    collections::{BTreeMap, HashSet},
    convert::TryInto,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

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
) -> CheckBalanceAgainstTransactionResponse
{
    let sponsor_for_gas: H160 = contract_account
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

    let sponsor_for_collateral: H160 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_for_collateral)
        .unwrap_or_default();

    let balance_for_collateral: U512 = contract_account
        .as_ref()
        .map(|a| a.sponsor_info.sponsor_balance_for_collateral)
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
}

impl RpcImpl {
    pub fn new(
        exit: Arc<(Mutex<bool>, Condvar)>, consensus: SharedConsensusGraph,
        network: Arc<NetworkService>, tx_pool: SharedTransactionPool,
        accounts: Arc<AccountProvider>,
    ) -> Self
    {
        let data_man = consensus.get_data_manager().clone();

        RpcImpl {
            exit,
            consensus,
            data_man,
            network,
            tx_pool,
            accounts,
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }
}

// Cfx RPC implementation
impl RpcImpl {
    pub fn best_block_hash(&self) -> JsonRpcResult<H256> {
        info!("RPC Request: cfx_getBestBlockHash()");
        Ok(self.consensus.best_block_hash().into())
    }

    pub fn gas_price(&self) -> RpcResult<U256> {
        let consensus_graph = self.consensus_graph();
        info!("RPC Request: cfx_gasPrice()");
        Ok(consensus_graph
            .gas_price()
            .unwrap_or(cfxcore::consensus_parameters::ONE_GDRIP_IN_DRIP.into())
            .into())
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
    ) -> RpcResult<Option<RpcBlock>> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        info!("RPC Request: cfx_getBlockByEpochNumber epoch_number={:?} include_txs={:?}", epoch_num, include_txs);

        let epoch_height = consensus_graph
            .get_height_from_epoch_number(epoch_num.into())
            .map_err(RpcError::invalid_params)?;

        let pivot_hash = inner
            .get_pivot_hash_from_epoch_number(epoch_height)
            .map_err(RpcError::invalid_params)?;

        let maybe_block = self
            .data_man
            .block_by_hash(&pivot_hash, false /* update_cache */)
            .map(|b| RpcBlock::new(&*b, inner, &self.data_man, include_txs));

        Ok(maybe_block)
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
    ) -> RpcResult<Option<RpcBlock>> {
        let consensus_graph = self.consensus_graph();
        let hash: H256 = hash.into();
        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );

        let inner = &*consensus_graph.inner.read();

        let maybe_block = self
            .data_man
            .block_by_hash(&hash, false /* update_cache */)
            .map(|b| RpcBlock::new(&*b, inner, &self.data_man, include_txs));

        Ok(maybe_block)
    }

    pub fn block_by_hash_with_pivot_assumption(
        &self, block_hash: H256, pivot_hash: H256, epoch_number: U64,
    ) -> RpcResult<RpcBlock> {
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();
        let block_hash: H256 = block_hash.into();
        let pivot_hash: H256 = pivot_hash.into();
        let epoch_number = epoch_number.as_usize() as u64;

        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        inner
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(RpcError::invalid_params)?;

        let block = self
            .data_man
            .block_by_hash(&block_hash, false /* update_cache */)
            .ok_or_else(|| RpcError::invalid_params("Block not found"))?;

        debug!("Build RpcBlock {}", block.hash());
        Ok(RpcBlock::new(&*block, inner, &self.data_man, true))
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
        &self, address: Base32Address, num: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<U256> {
        // TODO: add check for address.network

        let consensus_graph = self.consensus_graph();

        let num = num.unwrap_or(BlockHashOrEpochNumber::EpochNumber(
            EpochNumber::LatestState,
        ));

        info!(
            "RPC Request: cfx_getNextNonce address={:?} epoch_num={:?}",
            address, num
        );

        let address: H160 = address.try_into()?;
        consensus_graph.next_nonce(address, num.into())
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

    pub fn chain(&self) -> JsonRpcResult<Vec<RpcBlock>> {
        info!("RPC Request: cfx_getChain");
        let consensus_graph = self.consensus_graph();
        let inner = &*consensus_graph.inner.read();

        let construct_block = |hash| {
            let block = self
                .data_man
                .block_by_hash(hash, false /* update_cache */)
                .expect("Error to get block by hash");

            RpcBlock::new(&*block, inner, &self.data_man, true)
        };

        Ok(inner
            .all_blocks_with_topo_order()
            .iter()
            .map(construct_block)
            .collect())
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

    pub fn get_status(&self) -> JsonRpcResult<RpcStatus> {
        let best_info = self.consensus.best_info();
        let best_hash = best_info.best_block_hash;
        let epoch_number = best_info.best_epoch_number;
        let block_number = self.consensus.block_count();
        let tx_count = self.tx_pool.total_unpacked();

        Ok(RpcStatus {
            best_hash: H256::from(best_hash),
            chain_id: best_info.chain_id.into(),
            epoch_number: epoch_number.into(),
            block_number: block_number.into(),
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
}

// Debug RPC implementation
impl RpcImpl {
    pub fn clear_tx_pool(&self) -> JsonRpcResult<()> {
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

    pub fn tx_inspect(&self, hash: H256) -> JsonRpcResult<TxWithPoolInfo> {
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
            let required_balance = tx.value
                + tx.gas * tx.gas_price
                + tx.storage_limit * ONE_CFX_IN_DRIP / 1024;
            ret.local_balance_enough = local_balance > required_balance;
            ret.state_balance_enough = state_balance > required_balance;
            ret.local_balance = local_balance;
            ret.local_nonce = local_nonce;
            ret.state_balance = state_balance;
            ret.state_nonce = state_nonce;
        }
        Ok(ret)
    }

    pub fn txs_from_pool(
        &self, address: Option<H160>,
    ) -> JsonRpcResult<Vec<RpcTransaction>> {
        let (ready_txs, deferred_txs) = self.tx_pool.content(address);
        let converter = |tx: &Arc<SignedTransaction>| -> RpcTransaction {
            RpcTransaction::from_signed(&tx, None)
        };
        let result = ready_txs
            .iter()
            .map(converter)
            .chain(deferred_txs.iter().map(converter))
            .collect();
        return Ok(result);
    }

    pub fn txpool_content(
        &self, address: Option<H160>,
    ) -> JsonRpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content(address);
        let converter = |tx: Arc<SignedTransaction>| -> RpcTransaction {
            RpcTransaction::from_signed(&tx, None)
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
        &self, address: Option<H160>,
    ) -> JsonRpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content(address);
        let converter = |tx: Arc<SignedTransaction>| -> String {
            let to = match tx.action {
                Action::Create => "<Create contract>".into(),
                Action::Call(addr) => format!("{:?}", addr),
            };

            format!(
                "{}: {:?} drip + {:?} gas * {:?} drip",
                to, tx.value, tx.gas, tx.gas_price
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

    pub fn txpool_status(&self) -> JsonRpcResult<BTreeMap<String, usize>> {
        let (ready_len, deferred_len, received_len, unexecuted_len) =
            self.tx_pool.stats();

        let mut ret: BTreeMap<String, usize> = BTreeMap::new();
        ret.insert("ready".into(), ready_len);
        ret.insert("deferred".into(), deferred_len);
        ret.insert("received".into(), received_len);
        ret.insert("unexecuted".into(), unexecuted_len);

        Ok(ret)
    }

    pub fn accounts(&self) -> JsonRpcResult<Vec<H160>> {
        let accounts: Vec<Address> = self.accounts.accounts().map_err(|e| {
            warn!("Could not fetch accounts. With error {:?}", e);
            RpcError::internal_error()
        })?;
        Ok(accounts.into_iter().map(Into::into).collect::<Vec<H160>>())
    }

    pub fn new_account(&self, password: String) -> JsonRpcResult<H160> {
        let address: Address = self
            .accounts
            .new_account(&password.into())
            .map(Into::into)
            .map_err(|e| {
                warn!("Could not create account. With error {:?}", e);
                RpcError::internal_error()
            })?;
        Ok(address.into())
    }

    pub fn unlock_account(
        &self, address: H160, password: String, duration: Option<U128>,
    ) -> JsonRpcResult<bool> {
        let account: Address = address.into();
        let store = self.accounts.clone();
        let duration = match duration {
            None => None,
            Some(duration) => {
                let duration: U128 = duration.into();
                let v = duration.low_u64() as u32;
                if duration != v.into() {
                    return Err(RpcError::invalid_params(
                        "invalid duration number",
                    ));
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
                Err(RpcError::internal_error())
            }
        }
    }

    pub fn lock_account(&self, address: H160) -> JsonRpcResult<bool> {
        match self.accounts.lock_account(address.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("Unable to lock the account. With error {:?}", err);
                Err(RpcError::internal_error())
            }
        }
    }

    pub fn sign(
        &self, data: Bytes, address: H160, password: Option<String>,
    ) -> JsonRpcResult<H520> {
        let message = eth_data_hash(data.0);
        let password = password.map(Password::from);
        let signature =
            match self.accounts.sign(address.into(), password, message) {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("Unable to sign the message. With error {:?}", err);
                    return Err(RpcError::internal_error());
                }
            };
        Ok(H520(signature.into()))
    }

    pub fn save_node_db(&self) -> JsonRpcResult<()> {
        self.network.save_node_db();
        Ok(())
    }

    pub fn get_client_version(&self) -> JsonRpcResult<String> {
        Ok(format!("conflux-rust-{}", crate_version!()).into())
    }

    pub fn tx_inspect_pending(
        &self, address: Base32Address,
    ) -> RpcResult<TxPoolPendingInfo> {
        // TODO: add check for address.network
        let address: H160 = address.try_into()?;

        let mut ret = TxPoolPendingInfo::default();
        let (deferred_txs, _) = self.tx_pool.content(Some(address));
        let mut max_nonce: U256 = U256::from(0);
        let mut min_nonce: U256 = U256::max_value();
        for tx in deferred_txs.iter() {
            if tx.nonce > max_nonce {
                max_nonce = tx.nonce;
            }
            if tx.nonce < min_nonce {
                min_nonce = tx.nonce;
            }
        }
        ret.pending_count = deferred_txs.len();
        ret.min_nonce = min_nonce;
        ret.max_nonce = max_nonce;
        Ok(ret)
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
