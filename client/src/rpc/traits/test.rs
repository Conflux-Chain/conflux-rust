// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{
    BlameInfo, Block, Bytes, Receipt as RpcReceipt, Status as RpcStatus,
};
use cfx_types::H256;
use cfxcore::PeerInfo;
use jsonrpc_core::Result as RpcResult;
use jsonrpc_derive::rpc;
use network::node_table::NodeId;
use std::net::SocketAddr;

#[rpc(server)]
pub trait TestRpc {
    #[rpc(name = "sayhello")]
    fn say_hello(&self) -> RpcResult<String>;

    #[rpc(name = "getblockcount")]
    fn get_block_count(&self) -> RpcResult<u64>;

    #[rpc(name = "getgoodput")]
    fn get_goodput(&self) -> RpcResult<String>;

    #[rpc(name = "generate")]
    fn generate(
        &self, num_blocks: usize, num_txs: usize,
    ) -> RpcResult<Vec<H256>>;

    #[rpc(name = "generatefixedblock")]
    fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        adaptive: bool, difficulty: Option<u64>,
    ) -> RpcResult<H256>;

    #[rpc(name = "addnode")]
    fn add_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[rpc(name = "removenode")]
    fn drop_peer(&self, id: NodeId, addr: SocketAddr) -> RpcResult<()>;

    #[rpc(name = "getpeerinfo")]
    fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;

    /// Returns the JSON of whole chain
    #[rpc(name = "cfx_getChain")]
    fn chain(&self) -> RpcResult<Vec<Block>>;

    #[rpc(name = "stop")]
    fn stop(&self) -> RpcResult<()>;

    #[rpc(name = "getnodeid")]
    fn get_nodeid(&self, challenge: Vec<u8>) -> RpcResult<Vec<u8>>;

    #[rpc(name = "getstatus")]
    fn get_status(&self) -> RpcResult<RpcStatus>;

    #[rpc(name = "addlatency")]
    fn add_latency(&self, id: NodeId, latency_ms: f64) -> RpcResult<()>;

    #[rpc(name = "generateoneblock")]
    fn generate_one_block(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> RpcResult<H256>;

    #[rpc(name = "generateoneblockspecial")]
    fn generate_one_block_special(
        &self, num_txs: usize, block_size_limit: usize, num_txs_simple: usize,
        num_txs_erc20: usize,
    ) -> RpcResult<()>;

    #[rpc(name = "test_generatecustomblock")]
    fn generate_custom_block(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes,
        adaptive: Option<bool>,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateblockwithfaketxs")]
    fn generate_block_with_fake_txs(
        &self, raw: Bytes, adaptive: Option<bool>, tx_data_len: Option<usize>,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generateblockwithblameinfo")]
    fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize, blame_info: BlameInfo,
    ) -> RpcResult<H256>;

    #[rpc(name = "test_generate_block_with_nonce_and_timestamp")]
    fn generate_block_with_nonce_and_timestamp(
        &self, parent: H256, referees: Vec<H256>, raw: Bytes, nonce: u64,
        timestamp: u64, adaptive: bool,
    ) -> RpcResult<H256>;

    #[rpc(name = "gettransactionreceipt")]
    fn get_transaction_receipt(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<RpcReceipt>>;

    #[rpc(name = "expireblockgc")]
    fn expire_block_gc(&self, timeout: u64) -> RpcResult<()>;

    #[rpc(name = "test_sendUsableGenesisAccounts")]
    fn send_usable_genesis_accounts(
        &self, account_start_index: usize,
    ) -> RpcResult<Bytes>;

    #[rpc(name = "set_db_crash")]
    fn set_db_crash(
        &self, crash_probability: f64, crash_exit_code: i32,
    ) -> RpcResult<()>;

    #[rpc(name = "save_node_db")]
    fn save_node_db(&self) -> RpcResult<()>;
}
