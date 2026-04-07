// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{pos::Block as PosBlock, BlameInfo, Block, Bytes};
use cfx_types::{H256, U256, U64};
use diem_types::{
    account_address::AccountAddress, transaction::TransactionPayload,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use network::{node_table::NodeId, PeerInfo};
use std::net::SocketAddr;

#[rpc(server, namespace = "test")]
pub trait TestRpc {
    #[method(name = "sayHello")]
    fn say_hello(&self) -> RpcResult<String>;

    #[method(name = "getBlockCount")]
    fn get_block_count(&self) -> RpcResult<u64>;

    #[method(name = "getGoodPut")]
    fn get_goodput(&self) -> RpcResult<String>;

    #[method(name = "generateEmptyBlocks")]
    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;

    #[method(name = "generateFixedBlock")]
    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>,
    ) -> RpcResult<H256>;

    #[method(name = "addNode")]
    fn add_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[method(name = "removeNode")]
    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[method(name = "getPeerInfo")]
    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;

    /// Returns the JSON of whole chain
    #[method(name = "getChain")]
    fn chain(&self) -> RpcResult<Vec<Block>>;

    #[method(name = "stop")]
    fn stop(&self) -> RpcResult<()>;

    #[method(name = "getNodeId")]
    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;

    #[method(name = "addLatency")]
    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;

    #[method(name = "generateOneBlock")]
    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256>;

    #[method(name = "generateOneBlockWithDirectTxGen")]
    fn generate_one_block_with_direct_txgen(
        &self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize,
        num_txs_erc20: usize,
    ) -> RpcResult<H256>;

    #[method(name = "generateCustomBlock")]
    fn generate_custom_block(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes,
        adaptive: Option<bool>, custom: Option<Vec<Bytes>>,
    ) -> RpcResult<H256>;

    #[method(name = "generateBlockWithFakeTxs")]
    fn generate_block_with_fake_txs(
        &self, raw: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>,
    ) -> RpcResult<H256>;

    #[method(name = "generateBlockWithBlameInfo")]
    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256>;

    #[method(name = "generateBlockWithNonceAndTimestamp")]
    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256>;

    #[method(name = "getBlockStatus")]
    fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)>;

    #[method(name = "expireBlockGc")]
    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;

    #[method(name = "getPivotChainAndWeight")]
    fn get_pivot_chain_and_weight(
        &self, height_range: Option<(u64, u64)>,
    ) -> RpcResult<Vec<(H256, U256)>>;

    #[method(name = "getExecutedInfo")]
    fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)>;

    #[method(name = "sendUsableGenesisAccounts")]
    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes>;

    #[method(name = "setDbCrash")]
    fn set_db_crash(
        &self, crash_probability: f64, crash_exit_code: i32,
    ) -> RpcResult<()>;

    #[method(name = "saveNodeDb")]
    fn save_node_db(&self) -> RpcResult<()>;

    #[method(name = "posRegister")]
    fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> RpcResult<(Bytes, AccountAddress)>;

    #[method(name = "posUpdateVotingPower")]
    fn pos_update_voting_power(
        &self, pos_account: AccountAddress, increased_voting_power: U64,
    ) -> RpcResult<()>;

    #[method(name = "posStopElection")]
    fn pos_stop_election(&self) -> RpcResult<Option<u64>>;

    #[method(name = "posStartVoting")]
    fn pos_start_voting(&self, initialize: bool) -> RpcResult<()>;

    #[method(name = "posStopVoting")]
    fn pos_stop_voting(&self) -> RpcResult<()>;

    #[method(name = "posVotingStatus")]
    fn pos_voting_status(&self) -> RpcResult<bool>;

    #[method(name = "posStart")]
    fn pos_start(&self) -> RpcResult<()>;

    #[method(name = "posForceVoteProposal")]
    fn pos_force_vote_proposal(&self, block_id: H256) -> RpcResult<()>;

    #[method(name = "posForcePropose")]
    fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> RpcResult<()>;

    #[method(name = "posTriggerTimeout")]
    fn pos_trigger_timeout(&self, timeout_type: String) -> RpcResult<()>;

    #[method(name = "posForceSignPivotDecision")]
    fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> RpcResult<()>;

    #[method(name = "posGetChosenProposal")]
    fn pos_get_chosen_proposal(&self) -> RpcResult<Option<PosBlock>>;
}
