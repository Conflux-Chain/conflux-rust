// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use parking_lot::{Condvar, Mutex};

use cfx_types::{Address, H256, U128};
use cfxcore::{PeerInfo, SharedConsensusGraph, SharedTransactionPool};
use ethcore_accounts::AccountProvider;
use ethkey::Password;
use keccak_hash::keccak;
use primitives::{Action, SignedTransaction};

use network::{
    node_table::{Node, NodeEndpoint, NodeEntry, NodeId},
    throttling::{self, THROTTLING_SERVICE},
    NetworkService, SessionDetails, UpdateNodeOperation,
};

use crate::accounts::{account_provider, keys_path};

use crate::rpc::types::{
    Block as RpcBlock, BlockHashOrEpochNumber, Bytes, EpochNumber,
    Receipt as RpcReceipt, Status as RpcStatus, Transaction as RpcTransaction,
    H160 as RpcH160, H256 as RpcH256, H520 as RpcH520, U128 as RpcU128,
    U256 as RpcU256, U64 as RpcU64,
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

pub struct RpcImpl {
    exit: Arc<(Mutex<bool>, Condvar)>,
    consensus: SharedConsensusGraph,
    network: Arc<NetworkService>,
    tx_pool: SharedTransactionPool,
    accounts: Arc<AccountProvider>,
}

impl RpcImpl {
    pub fn new(
        exit: Arc<(Mutex<bool>, Condvar)>, consensus: SharedConsensusGraph,
        network: Arc<NetworkService>, tx_pool: SharedTransactionPool,
    ) -> Self
    {
        let accounts = Arc::new(
            account_provider(Some(keys_path()), None)
                .ok()
                .expect("failed to initialize account provider"),
        );
        RpcImpl {
            exit,
            consensus,
            network,
            tx_pool,
            accounts,
        }
    }
}

// Cfx RPC implementation
impl RpcImpl {
    pub fn best_block_hash(&self) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_getBestBlockHash()");
        Ok(self.consensus.best_block_hash().into())
    }

    pub fn gas_price(&self) -> RpcResult<RpcU256> {
        info!("RPC Request: cfx_gasPrice()");
        Ok(self.consensus.gas_price().unwrap_or(0.into()).into())
    }

    pub fn epoch_number(
        &self, epoch_num: Option<EpochNumber>,
    ) -> RpcResult<RpcU256> {
        let epoch_num = epoch_num.unwrap_or(EpochNumber::LatestMined);
        info!("RPC Request: cfx_epochNumber({:?})", epoch_num);
        match self
            .consensus
            .get_height_from_epoch_number(epoch_num.into())
        {
            Ok(height) => Ok(height.into()),
            Err(e) => Err(RpcError::invalid_params(e)),
        }
    }

    pub fn block_by_epoch_number(
        &self, epoch_num: EpochNumber, include_txs: bool,
    ) -> RpcResult<RpcBlock> {
        let inner = &*self.consensus.inner.read();
        info!("RPC Request: cfx_getBlockByEpochNumber epoch_number={:?} include_txs={:?}", epoch_num, include_txs);
        let epoch_height = self
            .consensus
            .get_height_from_epoch_number(epoch_num.into())
            .map_err(|err| RpcError::invalid_params(err))?;
        inner
            .get_hash_from_epoch_number(epoch_height)
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|hash| {
                let block = self
                    .consensus
                    .data_man
                    .block_by_hash(&hash, false /* update_cache */)
                    .unwrap();
                Ok(RpcBlock::new(&*block, inner, include_txs))
            })
    }

    pub fn block_by_hash(
        &self, hash: RpcH256, include_txs: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let hash: H256 = hash.into();
        info!(
            "RPC Request: cfx_getBlockByHash hash={:?} include_txs={:?}",
            hash, include_txs
        );
        let inner = &*self.consensus.inner.read();

        if let Some(block) = self
            .consensus
            .data_man
            .block_by_hash(&hash, false /* update_cache */)
        {
            let result_block = Some(RpcBlock::new(&*block, inner, include_txs));
            Ok(result_block)
        } else {
            Ok(None)
        }
    }

    pub fn block_by_hash_with_pivot_assumption(
        &self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64,
    ) -> RpcResult<RpcBlock> {
        let inner = &*self.consensus.inner.read();

        let block_hash: H256 = block_hash.into();
        let pivot_hash: H256 = pivot_hash.into();
        let epoch_number = epoch_number.as_usize() as u64;
        info!(
            "RPC Request: cfx_getBlockByHashWithPivotAssumption block_hash={:?} pivot_hash={:?} epoch_number={:?}",
            block_hash, pivot_hash, epoch_number
        );

        inner
            .check_block_pivot_assumption(&pivot_hash, epoch_number)
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|_| {
                if let Some(block) = self
                    .consensus
                    .data_man
                    .block_by_hash(&block_hash, false /* update_cache */)
                {
                    debug!("Build RpcBlock {}", block.hash());
                    let result_block = RpcBlock::new(&*block, inner, true);
                    Ok(result_block)
                } else {
                    Err(RpcError::invalid_params(
                        "Error: can not find expected block".to_owned(),
                    ))
                }
            })
    }

    pub fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>> {
        info!("RPC Request: cfx_getBlocks epoch_number={:?}", num);

        self.consensus
            .get_block_hashes_by_epoch(num.into())
            .map_err(|err| RpcError::invalid_params(err))
            .and_then(|vec| Ok(vec.into_iter().map(|x| x.into()).collect()))
    }

    pub fn transaction_count(
        &self, address: RpcH160, num: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<RpcU256> {
        let num = num.unwrap_or(BlockHashOrEpochNumber::EpochNumber(
            EpochNumber::LatestState,
        ));
        info!(
            "RPC Request: cfx_getTransactionCount address={:?} epoch_num={:?}",
            address, num
        );

        self.consensus
            .transaction_count(address.into(), num.into())
            .map_err(|err| RpcError::invalid_params(err))
            .map(|x| x.into())
    }
}

// Test RPC implementation
impl RpcImpl {
    pub fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()> {
        match self.network.add_latency(id, latency_ms) {
            Ok(_) => Ok(()),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn add_peer(
        &self, node_id: NodeId, address: SocketAddr,
    ) -> RpcResult<()> {
        let node = NodeEntry {
            id: node_id,
            endpoint: NodeEndpoint {
                address,
                udp_port: address.port(),
            },
        };
        info!("RPC Request: add_peer({:?})", node.clone());
        match self.network.add_peer(node) {
            Ok(x) => Ok(x),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn chain(&self) -> RpcResult<Vec<RpcBlock>> {
        info!("RPC Request: cfx_getChain");
        let inner = &*self.consensus.inner.read();
        Ok(inner
            .all_blocks_with_topo_order()
            .iter()
            .map(|x| {
                RpcBlock::new(
                    self.consensus
                        .data_man
                        .block_by_hash(x, false /* update_cache */)
                        .expect("Error to get block by hash")
                        .as_ref(),
                    inner,
                    true,
                )
            })
            .collect())
    }

    pub fn drop_peer(
        &self, node_id: NodeId, address: SocketAddr,
    ) -> RpcResult<()> {
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

    pub fn get_block_count(&self) -> RpcResult<u64> {
        info!("RPC Request: get_block_count()");
        let count = self.consensus.block_count();
        info!("RPC Response: get_block_count={}", count);
        Ok(count)
    }

    pub fn get_goodput(&self) -> RpcResult<String> {
        info!("RPC Request: get_goodput");
        let mut set = HashSet::new();
        let mut min = std::u64::MAX;
        let mut max: u64 = 0;
        for key in self.consensus.inner.read().hash_to_arena_indices.keys() {
            if let Some(block) = self
                .consensus
                .data_man
                .block_by_hash(key, false /* update_cache */)
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
            for key in self.consensus.inner.read().hash_to_arena_indices.keys()
            {
                if let Some(block) = self
                    .consensus
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

    pub fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>> {
        match self.network.sign_challenge(challenge) {
            Ok(r) => Ok(r),
            Err(_) => Err(RpcError::internal_error()),
        }
    }

    pub fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>> {
        info!("RPC Request: get_peer_info");
        match self.network.get_peer_info() {
            None => Ok(Vec::new()),
            Some(peers) => Ok(peers),
        }
    }

    pub fn get_status(&self) -> RpcResult<RpcStatus> {
        let best_hash = self.consensus.best_block_hash();
        let block_number = self.consensus.block_count();
        let tx_count = self.tx_pool.total_unpacked();
        if let Some(epoch_number) =
            self.consensus.get_block_epoch_number(&best_hash)
        {
            Ok(RpcStatus {
                best_hash: RpcH256::from(best_hash),
                epoch_number,
                block_number,
                pending_tx_number: tx_count,
            })
        } else {
            Err(RpcError::internal_error())
        }
    }

    /// The first element is true if the tx is executed in a confirmed block.
    /// The second element indicate the execution result (standin
    /// for receipt)
    pub fn get_transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>> {
        let maybe_receipt =
            self.consensus.get_transaction_info_by_hash(&tx_hash).map(
                |(tx, receipt, address)| RpcReceipt::new(tx, receipt, address),
            );
        Ok(maybe_receipt)
    }

    pub fn say_hello(&self) -> RpcResult<String> { Ok("Hello, world".into()) }

    pub fn stop(&self) -> RpcResult<()> {
        *self.exit.0.lock() = true;
        self.exit.1.notify_all();

        Ok(())
    }
}

// Debug RPC implementation
impl RpcImpl {
    pub fn clear_tx_pool(&self) -> RpcResult<()> {
        self.tx_pool.clear_tx_pool();
        Ok(())
    }

    pub fn net_node(&self, id: NodeId) -> RpcResult<Option<(String, Node)>> {
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
    ) -> RpcResult<Option<usize>> {
        Ok(self.network.disconnect_node(&id, op))
    }

    pub fn net_sessions(
        &self, node_id: Option<NodeId>,
    ) -> RpcResult<Vec<SessionDetails>> {
        match self.network.get_detailed_sessions(node_id.into()) {
            None => Ok(Vec::new()),
            Some(sessions) => Ok(sessions),
        }
    }

    pub fn net_throttling(&self) -> RpcResult<throttling::Service> {
        Ok(THROTTLING_SERVICE.read().clone())
    }

    pub fn tx_inspect(
        &self, hash: RpcH256,
    ) -> RpcResult<BTreeMap<String, String>> {
        let mut ret: BTreeMap<String, String> = BTreeMap::new();
        let hash: H256 = hash.into();
        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            ret.insert("exist".into(), "true".into());
            if self.tx_pool.check_tx_packed_in_deferred_pool(&hash) {
                ret.insert("packed".into(), "true".into());
            } else {
                ret.insert("packed".into(), "false".into());
            }
            let (local_nonce, local_balance) =
                self.tx_pool.get_local_account_info(&tx.sender());
            let (state_nonce, state_balance) =
                self.tx_pool.get_state_account_info(&tx.sender());
            ret.insert(
                "local nonce".into(),
                serde_json::to_string(&local_nonce).unwrap(),
            );
            ret.insert(
                "local balance".into(),
                serde_json::to_string(&local_balance).unwrap(),
            );
            ret.insert(
                "state nonce".into(),
                serde_json::to_string(&state_nonce).unwrap(),
            );
            ret.insert(
                "state balance".into(),
                serde_json::to_string(&state_balance).unwrap(),
            );
        } else {
            ret.insert("exist".into(), "false".into());
        }
        Ok(ret)
    }

    pub fn txpool_content(
        &self,
    ) -> RpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content();
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
        &self,
    ) -> RpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    > {
        let (ready_txs, deferred_txs) = self.tx_pool.content();
        let converter = |tx: Arc<SignedTransaction>| -> String {
            let to = match tx.action {
                Action::Create => "<Create contract>".into(),
                Action::Call(addr) => format!("{:?}", addr),
            };

            format!(
                "{}: {:?} wei + {:?} gas * {:?} wei",
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

    pub fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>> {
        let (ready_len, deferred_len, received_len, unexecuted_len) =
            self.tx_pool.stats();

        let mut ret: BTreeMap<String, usize> = BTreeMap::new();
        ret.insert("ready".into(), ready_len);
        ret.insert("deferred".into(), deferred_len);
        ret.insert("received".into(), received_len);
        ret.insert("unexecuted".into(), unexecuted_len);

        Ok(ret)
    }

    pub fn accounts(&self) -> RpcResult<Vec<RpcH160>> {
        let accounts: Vec<Address> = self.accounts.accounts().map_err(|e| {
            warn!("Could not fetch accounts. With error {:?}", e);
            RpcError::internal_error()
        })?;
        Ok(accounts
            .into_iter()
            .map(Into::into)
            .collect::<Vec<RpcH160>>())
    }

    pub fn new_account(&self, password: String) -> RpcResult<RpcH160> {
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
        &self, address: RpcH160, password: String, duration: Option<RpcU128>,
    ) -> RpcResult<bool> {
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

    pub fn lock_account(&self, address: RpcH160) -> RpcResult<bool> {
        match self.accounts.lock_account(address.into()) {
            Ok(_) => Ok(true),
            Err(err) => {
                warn!("Unable to lock the account. With error {:?}", err);
                Err(RpcError::internal_error())
            }
        }
    }

    pub fn sign(
        &self, data: Bytes, address: RpcH160, password: Option<String>,
    ) -> RpcResult<RpcH520> {
        let message = self.eth_data_hash(data.0);
        let password = password.map(|s| Password::from(s));
        let signature =
            match self.accounts.sign(address.into(), password, message) {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("Unable to sign the message. With error {:?}", err);
                    return Err(RpcError::internal_error());
                }
            };
        Ok(RpcH520(signature.into()))
    }

    /// Returns a eth_sign-compatible hash of data to sign.
    /// The data is prepended with special message to prevent
    /// malicious DApps from using the function to sign forged transactions.
    fn eth_data_hash(&self, mut data: Vec<u8>) -> H256 {
        let mut message_data =
            format!("\x19Ethereum Signed Message:\n{}", data.len())
                .into_bytes();
        message_data.append(&mut data);
        keccak(message_data)
    }
}
