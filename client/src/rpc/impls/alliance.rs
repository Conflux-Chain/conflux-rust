// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use delegate::delegate;

use crate::rpc::{
    impls::{cfx::RpcImplConfiguration, common::RpcImpl as CommonImpl},
    traits::{cfx::Cfx, debug::DebugRpc, test::TestRpc},
    types::{
        Account as RpcAccount, BFTStates, BlameInfo, Block as RpcBlock,
        BlockHashOrEpochNumber, Bytes, CallRequest, ConsensusGraphStates,
        EpochNumber, Filter as RpcFilter, Log as RpcLog, Receipt as RpcReceipt,
        SendTxRequest, Status as RpcStatus, SyncGraphStates,
        Transaction as RpcTransaction, H160 as RpcH160, H256 as RpcH256,
        H520 as RpcH520, U128 as RpcU128, U256 as RpcU256, U64 as RpcU64,
    },
};
use cfx_types::{Public, H256};
use cfxcore::{
    alliance_tree_graph::{
        bft::executor::Executor, blockgen::TGBlockGenerator,
    },
    block_parameters::MAX_BLOCK_SIZE_IN_BYTES,
    state_exposer::STATE_EXPOSER,
    PeerInfo, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use jsonrpc_core::{BoxFuture, Error as RpcError, Result as RpcResult};
use keccak_hash::keccak;
use libra_crypto::secp256k1::Secp256k1PublicKey;
use libra_types::{
    account_address::AccountAddress, transaction::SignedTransaction,
    validator_public_keys::ValidatorPublicKeys,
    validator_set::ValidatorSet as RawValidatorSet,
};
use network::{
    node_table::{Node, NodeId},
    throttling, SessionDetails, UpdateNodeOperation,
};
use parking_lot::RwLock;
use primitives::TransactionWithSignature;
use rlp::Rlp;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

pub struct RpcImpl {
    //config: RpcImplConfiguration,
    //consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    block_gen: Arc<TGBlockGenerator>,
    // tx_gen: SharedTransactionGenerator,
    executor: Arc<Executor>,
    // The manager for administrator transaction (for epoch change).
    admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
}

impl RpcImpl {
    pub fn new(
        _consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
        block_gen: Arc<TGBlockGenerator>, tx_pool: SharedTransactionPool,
        _config: RpcImplConfiguration, executor: Arc<Executor>,
        admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
    ) -> Self
    {
        RpcImpl {
            // consensus,
            sync,
            tx_pool,
            block_gen,
            /* config, */
            executor,
            admin_transaction,
        }
    }

    fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates> {
        let consensus_graph_states =
            STATE_EXPOSER.consensus_graph.lock().retrieve();
        Ok(ConsensusGraphStates::new(consensus_graph_states))
    }

    fn sync_graph_state(&self) -> RpcResult<SyncGraphStates> {
        let sync_graph_states = STATE_EXPOSER.sync_graph.lock().retrieve();
        Ok(SyncGraphStates::new(sync_graph_states))
    }

    fn bft_state(&self) -> RpcResult<BFTStates> {
        let bft_states = STATE_EXPOSER.bft.lock().retrieve();
        Ok(BFTStates::new(bft_states))
    }

    fn current_sync_phase(&self) -> RpcResult<String> {
        Ok(self.sync.current_sync_phase().name().into())
    }

    fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256> {
        info!("RPC Request: cfx_sendRawTransaction bytes={:?}", raw);

        let tx = Rlp::new(&raw.into_vec()).as_val().map_err(|err| {
            RpcError::invalid_params(format!("Error: {:?}", err))
        })?;

        self.send_transaction_with_signature(tx)
    }

    fn set_consortium_administrators(
        &self, admins: Vec<Public>,
    ) -> RpcResult<bool> {
        let mut vec_keys = Vec::new();
        for pubkey in admins {
            let account_address = AccountAddress::new(keccak(&pubkey).into());
            let pubkey = Secp256k1PublicKey::from_public(pubkey);
            let val_pub_key = ValidatorPublicKeys::new(
                account_address,
                pubkey,
                1, /* consensus_voting_power */
            );
            vec_keys.push(val_pub_key);
        }

        let validator_set = RawValidatorSet::new(vec_keys);
        self.executor.set_administrators((&validator_set).into());
        Ok(true)
    }

    fn send_new_consortium_member_trans(
        &self, admin_trans: SignedTransaction,
    ) -> RpcResult<()> {
        *self.admin_transaction.write() = Some(admin_trans);
        Ok(())
    }

    fn send_transaction_with_signature(
        &self, tx: TransactionWithSignature,
    ) -> RpcResult<RpcH256> {
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

    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256> {
        Ok(self
            .block_gen
            .generate_block(num_txs, block_size_limit, vec![]))
    }

    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>> {
        let mut result = Vec::new();
        for _ in 0..num_blocks {
            result.push(self.block_gen.generate_block(
                0,
                MAX_BLOCK_SIZE_IN_BYTES,
                vec![],
            ));
        }
        Ok(result)
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
            fn blocks_by_epoch(&self, num: EpochNumber) -> RpcResult<Vec<RpcH256>>;
            fn best_block_hash(&self) -> RpcResult<RpcH256>;
        }

        target self.rpc_impl {
            fn send_raw_transaction(&self, raw: Bytes) -> RpcResult<RpcH256>;
            fn set_consortium_administrators(&self, admins: Vec<Public>) -> RpcResult<bool>;
            fn send_new_consortium_member_trans(&self, admin_trans: SignedTransaction) -> RpcResult<()>;
        }
    }

    not_supported! {
        fn block_by_epoch_number(&self, epoch_num: EpochNumber, include_txs: bool) -> RpcResult<RpcBlock>;
        fn block_by_hash_with_pivot_assumption(&self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64) -> RpcResult<RpcBlock>;
        fn block_by_hash(&self, hash: RpcH256, include_txs: bool) -> RpcResult<Option<RpcBlock>>;
        fn epoch_number(&self, epoch_num: Option<EpochNumber>) -> RpcResult<RpcU256>;
        fn gas_price(&self) -> RpcResult<RpcU256>;
        fn transaction_count(&self, address: RpcH160, num: Option<BlockHashOrEpochNumber>) -> RpcResult<RpcU256>;

        fn admin(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcH160>;
        fn sponsor(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcH160>;
        fn sponsor_balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
        fn account(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcAccount>;
        fn balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
        fn staking_balance(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
        fn collateral_for_storage(&self, address: RpcH160, num: Option<EpochNumber>) -> BoxFuture<RpcU256>;
        fn call(&self, request: CallRequest, epoch: Option<EpochNumber>) -> RpcResult<Bytes>;
        fn code(&self, address: RpcH160, epoch_num: Option<EpochNumber>) -> BoxFuture<Bytes>;
        fn estimate_gas(&self, request: CallRequest, epoch_num: Option<EpochNumber>) -> RpcResult<RpcU256>;
        fn get_logs(&self, filter: RpcFilter) -> BoxFuture<Vec<RpcLog>>;
        fn transaction_by_hash(&self, hash: RpcH256) -> BoxFuture<Option<RpcTransaction>>;
        fn transaction_receipt(&self, tx_hash: RpcH256) -> BoxFuture<Option<RpcReceipt>>;

        fn interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
        fn accumulate_interest_rate(&self, num: Option<EpochNumber>) -> RpcResult<RpcU256>;
    }
}

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
        target self.common {
            fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;
            fn add_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn drop_peer(&self, node_id: NodeId, address: SocketAddr) -> RpcResult<()>;
            fn get_block_count(&self) -> RpcResult<u64>;
            fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;
            fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;
            fn get_status(&self) -> RpcResult<RpcStatus>;
            fn say_hello(&self) -> RpcResult<String>;
            fn stop(&self) -> RpcResult<()>;
            fn save_node_db(&self) -> RpcResult<()>;
        }

        target self.rpc_impl {
            fn generate_one_block(&self, num_txs: usize, block_size_limit: usize) -> RpcResult<H256>;
            fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;
        }
    }

    not_supported! {
        fn chain(&self) -> RpcResult<Vec<RpcBlock>>;
        fn get_goodput(&self) -> RpcResult<String>;

        fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;
        fn generate_block_with_blame_info(&self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo) -> RpcResult<H256>;
        fn generate_block_with_fake_txs(&self, raw_txs_without_data: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>) -> RpcResult<H256>;
        fn generate_custom_block(&self, parent_hash: H256, referee: Vec<H256>, raw_txs: Bytes, adaptive: Option<bool>) -> RpcResult<H256>;
        fn generate_fixed_block(&self, parent_hash: H256, referee: Vec<H256>, num_txs: usize, adaptive: bool, difficulty: Option<u64>) -> RpcResult<H256>;
        fn generate_one_block_with_direct_txgen(&self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize, num_txs_erc20: usize) -> RpcResult<()>;
        fn generate_block_with_nonce_and_timestamp(&self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: u64, timestamp: u64, adaptive: bool) -> RpcResult<H256>;
        fn send_usable_genesis_accounts(& self, account_start_index: usize) -> RpcResult<Bytes>;
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

impl DebugRpc for DebugRpcImpl {
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
            fn current_sync_phase(&self) -> RpcResult<String>;
            fn consensus_graph_state(&self) -> RpcResult<ConsensusGraphStates>;
            fn sync_graph_state(&self) -> RpcResult<SyncGraphStates>;
            fn bft_state(&self) -> RpcResult<BFTStates>;
        }
    }

    not_supported! {
        fn send_transaction(&self, tx: SendTxRequest, password: Option<String>) -> BoxFuture<RpcH256>;
    }
}
