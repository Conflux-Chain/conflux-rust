// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{pos::Block as PosBlock, BlameInfo, Block, Bytes};
use cfx_types::{H256, U256, U64};
use cfxcore::PeerInfo;
use diem_types::{
    account_address::AccountAddress, transaction::TransactionPayload,
};
use jsonrpc_core::Result as RpcResult;
use jsonrpc_derive::rpc;
use network::node_table::NodeId;
use std::net::SocketAddr;

#[rpc(server)]
pub trait TestRpc {
    #[rpc(name = "test_sayHello")]
    fn say_hello(&self) -> RpcResult<String>;

    #[rpc(name = "test_getBlockCount")]
    fn get_block_count(&self) -> RpcResult<u64>;

    #[rpc(name = "test_getGoodPut")]
    fn get_goodput(&self) -> RpcResult<String>;

    #[rpc(name = "test_generateEmptyBlocks")]
    fn generate_empty_blocks(&self, num_blocks: usize) -> RpcResult<Vec<H256>>;

    #[rpc(name = "test_generateFixedBlock")]
    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>, pos_reference: Option<H256>,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_addNode")]
    fn add_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[rpc(name = "test_removeNode")]
    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[rpc(name = "test_getPeerInfo")]
    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;

    /// Returns the JSON of whole chain
    #[rpc(name = "test_getChain")]
    fn chain(&self) -> RpcResult<Vec<Block>>;

    #[rpc(name = "test_stop")]
    fn stop(&self) -> RpcResult<()>;

    #[rpc(name = "test_getNodeId")]
    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;

    #[rpc(name = "test_addLatency")]
    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;

    #[rpc(name = "test_generateOneBlock")]
    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateOneBlockWithDirectTxGen")]
    fn generate_one_block_with_direct_txgen(
        &self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize,
        num_txs_erc20: usize,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateCustomBlock")]
    fn generate_custom_block(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes,
        adaptive: Option<bool>, custom: Option<Vec<Bytes>>,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateBlockWithFakeTxs")]
    fn generate_block_with_fake_txs(
        &self, raw: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateBlockWithBlameInfo")]
    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateBlockWithNonceAndTimestamp")]
    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: U256,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_getBlockStatus")]
    fn get_block_status(&self, block_hash: H256) -> RpcResult<(u8, bool)>;

    #[rpc(name = "test_expireBlockGc")]
    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;

    #[rpc(name = "test_getPivotChainAndWeight")]
    fn get_pivot_chain_and_weight(
        &self, height_range: Option<(u64, u64)>,
    ) -> RpcResult<Vec<(H256, U256)>>;

    #[rpc(name = "test_getExecutedInfo")]
    fn get_executed_info(&self, block_hash: H256) -> RpcResult<(H256, H256)>;

    #[rpc(name = "test_sendUsableGenesisAccounts")]
    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes>;

    #[rpc(name = "test_setDbCrash")]
    fn set_db_crash(
        &self, crash_probability: f64, crash_exit_code: i32,
    ) -> RpcResult<()>;

    #[rpc(name = "test_saveNodeDb")]
    fn save_node_db(&self) -> RpcResult<()>;

    #[rpc(name = "test_posRegister")]
    fn pos_register(
        &self, voting_power: U64, version: Option<u8>,
    ) -> RpcResult<(Bytes, AccountAddress)>;

    #[rpc(name = "test_posUpdateVotingPower")]
    fn pos_update_voting_power(
        &self, pos_account: AccountAddress, increased_voting_power: U64,
    ) -> RpcResult<()>;

    #[rpc(name = "test_posStopElection")]
    fn pos_stop_election(&self) -> RpcResult<Option<u64>>;

    #[rpc(name = "test_posStartVoting")]
    fn pos_start_voting(&self, initialize: bool) -> RpcResult<()>;

    #[rpc(name = "test_posStopVoting")]
    fn pos_stop_voting(&self) -> RpcResult<()>;

    #[rpc(name = "test_posVotingStatus")]
    fn pos_voting_status(&self) -> RpcResult<bool>;

    #[rpc(name = "test_posStart")]
    fn pos_start(&self) -> RpcResult<()>;

    #[rpc(name = "test_posForceVoteProposal")]
    fn pos_force_vote_proposal(&self, block_id: H256) -> RpcResult<()>;

    #[rpc(name = "test_posForcePropose")]
    fn pos_force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> RpcResult<()>;

    #[rpc(name = "test_posTriggerTimeout")]
    fn pos_trigger_timeout(&self, timeout_type: String) -> RpcResult<()>;

    #[rpc(name = "test_posForceSignPivotDecision")]
    fn pos_force_sign_pivot_decision(
        &self, block_hash: H256, height: U64,
    ) -> RpcResult<()>;

    #[rpc(name = "test_posGetChosenProposal")]
    fn pos_get_chosen_proposal(&self) -> RpcResult<Option<PosBlock>>;
}
