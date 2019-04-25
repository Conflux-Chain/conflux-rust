// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{
    Block, Bytes, EpochNumber, Receipt as RpcReceipt, Status as RpcStatus,
    Transaction, Transaction as RpcTransaction, H160 as RpcH160,
    H256 as RpcH256, U256 as RpcU256, U64 as RpcU64,
};
use cfx_types::H256;
use cfxcore::PeerInfo;
use jsonrpc_core::Result as RpcResult;
use jsonrpc_macros::{build_rpc_trait, Trailing};
use network::node_table::NodeId;
use std::{collections::BTreeMap, net::SocketAddr};

build_rpc_trait! {
    /// Cfx rpc interface.
    pub trait Cfx {
//        /// Returns protocol version encoded as a string (quotes are necessary).
//        #[rpc(name = "cfx_protocolVersion")]
//        fn protocol_version(&self) -> RpcResult<String>;
//
        /// Returns the number of hashes per second that the node is mining with.
//        #[rpc(name = "cfx_hashrate")]
//        fn hashrate(&self) -> RpcResult<RpcU256>;

//        /// Returns block author.
//        #[rpc(name = "cfx_coinbase")]
//        fn author(&self) -> RpcResult<RpcH160>;

//        /// Returns true if client is actively mining new blocks.
//        #[rpc(name = "cfx_mining")]
//        fn is_mining(&self) -> RpcResult<bool>;

        /// Returns current gas price.
        #[rpc(name = "cfx_gasPrice")]
        fn gas_price(&self) -> RpcResult<RpcU256>;

//        /// Returns accounts list.
//        #[rpc(name = "cfx_accounts")]
//        fn accounts(&self) -> RpcResult<Vec<RpcH160>>;

        /// Returns highest epoch number.
        #[rpc(name = "cfx_epochNumber")]
        fn epoch_number(&self, Trailing<EpochNumber>) -> RpcResult<RpcU256>;

        /// Returns balance of the given account.
        #[rpc(name = "cfx_getBalance")]
        fn balance(&self, RpcH160, Trailing<EpochNumber>) -> RpcResult<RpcU256>;

//        /// Returns content of the storage at given address.
//        #[rpc(name = "cfx_getStorageAt")]
//        fn storage_at(&self, RpcH160, RpcU256, Trailing<BlockNumber>) -> BoxFuture<RpcH256>;

        /// Returns block with given hash.
        #[rpc(name = "cfx_getBlockByHash")]
        fn block_by_hash(&self, RpcH256, bool) -> RpcResult<Option<Block>>;

        /// Returns block with given hash and pivot chain assumption.
        #[rpc(name = "cfx_getBlockByHashWithPivotAssumption")]
        fn block_by_hash_with_pivot_assumption(&self, RpcH256, RpcH256, RpcU64) -> RpcResult<Block>;

        /// Returns block with given epoch number.
        #[rpc(name = "cfx_getBlockByEpochNumber")]
        fn block_by_epoch_number(&self, EpochNumber, bool) -> RpcResult<Block>;

        /// Returns best block hash.
        #[rpc(name = "cfx_getBestBlockHash")]
        fn best_block_hash(&self) -> RpcResult<RpcH256>;

        /// Returns the number of transactions sent from given address at given time (epoch number).
        #[rpc(name = "cfx_getTransactionCount")]
        fn transaction_count(&self, RpcH160, Trailing<EpochNumber>) -> RpcResult<RpcU256>;

//        /// Returns the number of transactions in a block with given hash.
//        #[rpc(name = "cfx_getBlockTransactionCountByHash")]
//        fn block_transaction_count_by_hash(&self, RpcH256) -> BoxFuture<Option<RpcU256>>;

//        /// Returns the number of transactions in a block with given block number.
//        #[rpc(name = "cfx_getBlockTransactionCountByNumber")]
//        fn block_trasaction_count_by_number(&self, BlockNumber) -> BoxFuture<Option<RpcU256>>;

//        /// Returns the number of uncles in a block with given hash.
//        #[rpc(name = "cfx_getUncleCountByBlockHash")]
//        fn block_uncles_count_by_hash(&self, RpcH256) -> BoxFuture<Option<RpcU256>>;

//        /// Returns the number of uncles in a block with given block number.
//        #[rpc(name = "cfx_getUnclesCountByBlockNumber")]
//        fn block_uncles_count_by_number(&self, BlockNumber) -> BoxFuture<Option<RpcU256>>;

//        /// Returns the code at given address at given time (block number).
//        #[rpc(name = "cfx_getCode")]
//        fn code_at(&self, RpcH160, Trailing<BlockNumber>) -> BoxFuture<Bytes>;

        /// Sends signed transaction, returning its hash.
        #[rpc(name = "cfx_sendRawTransaction")]
        fn send_raw_transaction(&self, Bytes) -> RpcResult<RpcH256>;

//        /// @alias of `cfx_sendRawTransaction`.
//        #[rpc(name = "cfx_submitTransaction")]
//        fn submit_transaction(&self, Bytes) -> RpcResult<RpcH256>;

        /// Call contract, returning hte output data.
        #[rpc(name = "cfx_call")]
        fn call(&self, RpcTransaction, Trailing<EpochNumber>) -> RpcResult<Bytes>;

//        /// Estimate gas needed for execution of given contract.
//        #[rpc(name = "cfx_estimateGas")]
//        fn estimate_gas(&self, CallRequest, Trailing<BlockNumber>) -> BoxFuture<RpcU256>;

        /// Get transaction by its hash.
        #[rpc(name = "cfx_getTransactionByHash")]
        fn transaction_by_hash(&self, RpcH256) -> RpcResult<Option<Transaction>>;


        #[rpc(name = "cfx_estimateGas")]
        fn estimate_gas(&self, RpcTransaction) -> RpcResult<RpcU256>;

        #[rpc(name = "cfx_getBlocksByEpoch")]
        fn blocks_by_epoch(&self, EpochNumber) -> RpcResult<Vec<RpcH256>>;

//        #[rpc(name = "cfx_getAccount")]
//        fn account(&self, RpcH160, bool, RpcU64, Trailing<EpochNumber>) -> RpcResult<Account>;

//        /// Returns transaction at given block hash and index.
//        #[rpc(name = "cfx_getTransactionByBlockHashAndIndex")]
//        fn transaction_by_block_hash_and_index(&self, RpcH256, Index) -> BoxFuture<Option<Transaction>>;

//        /// Returns transaction by given block number and index.
//        #[rpc(name = "cfx_getTransactionByBlockNumberAndIndex")]
//        fn transaction_by_block_number_and_index(&self, BlockNumber, Index) -> BoxFuture<Option<Transaction>>;

//        /// Returns uncles at given block and index.
//        #[rpc(name = "cfx_getUnclesByBlockHashAndIndex")]
//        fn uncles_by_block_hash_and_index(&self, RpcH256, Index) -> BoxFuture<Option<Block>>;

//        /// Returns uncles at given block and index.
//        #[rpc(name = "cfx_getUnclesByBlockNumberAndIndex")]
//        fn uncles_by_block_number_and_index(&self, BlockNumber, Index) -> BoxFuture<Option<Block>>;
    }
}

build_rpc_trait! {
    pub trait TestRpc {
        #[rpc(name = "sayhello")]
        fn say_hello(&self) -> RpcResult<String>;

        #[rpc(name = "getbestblockhash")]
        fn get_best_block_hash(&self) -> RpcResult<H256>;

        #[rpc(name = "getblockcount")]
        fn get_block_count(&self) -> RpcResult<usize>;

        #[rpc(name = "generate")]
        fn generate(&self, usize, usize) -> RpcResult<Vec<H256>>;

        #[rpc(name = "generatefixedblock")]
        fn generate_fixed_block(&self, H256, Vec<H256>, usize) -> RpcResult<H256>;

        #[rpc(name = "addnode")]
        fn add_peer(&self, NodeId, SocketAddr) -> RpcResult<()>;

        #[rpc(name = "removenode")]
        fn drop_peer(&self, NodeId, SocketAddr) -> RpcResult<()>;

        #[rpc(name = "getpeerinfo")]
        fn get_peer_info(&self) -> RpcResult<Vec<PeerInfo>>;

        /// Returns the JSON of whole chain
        #[rpc(name = "cfx_getChain")]
        fn chain(&self) -> RpcResult<Vec<Block>>;

        #[rpc(name = "stop")]
        fn stop(&self) -> RpcResult<()>;

        #[rpc(name = "getnodeid")]
        fn get_nodeid(&self, Vec<u8>) -> RpcResult<Vec<u8>>;

        #[rpc(name = "getstatus")]
        fn get_status(&self) -> RpcResult<RpcStatus>;

        #[rpc(name = "addlatency")]
        fn add_latency(&self, NodeId, f64) -> RpcResult<()>;

        #[rpc(name = "generateoneblock")]
        fn generate_one_block(&self, usize) -> RpcResult<H256>;

        #[rpc(name = "test_generatecustomblock")]
        fn generate_custom_block(&self, H256, Vec<H256>, Bytes) -> RpcResult<H256>;

        #[rpc(name = "test_generateblockwithfaketxs")]
        fn generate_block_with_fake_txs(&self, Bytes, Trailing<usize>) -> RpcResult<H256>;

        #[rpc(name = "gettransactionreceipt")]
        fn get_transaction_receipt(&self, H256) -> RpcResult<Option<RpcReceipt>>;
    }
}

build_rpc_trait! {
    pub trait DebugRpc {
        #[rpc(name = "txpool_status")]
        fn txpool_status(&self) -> RpcResult<BTreeMap<String, usize>>;

        #[rpc(name = "txpool_inspect")]
        fn txpool_inspect(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;

        #[rpc(name = "txpool_content")]
        fn txpool_content(&self) -> RpcResult<BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
    }
}
