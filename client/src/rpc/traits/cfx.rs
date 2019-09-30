// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::types::{
    Block, Bytes, EpochNumber, Filter as RpcFilter, Log as RpcLog,
    Receipt as RpcReceipt, Transaction, Transaction as RpcTransaction,
    H160 as RpcH160, H256 as RpcH256, U256 as RpcU256, U64 as RpcU64,
};
use crate::rpc::types::BlockHashOrEpochNumber;
use jsonrpc_core::Result as RpcResult;
use jsonrpc_derive::rpc;

/// Cfx rpc interface.
#[rpc]
pub trait Cfx {
    //        /// Returns protocol version encoded as a string (quotes are
    // necessary).        #[rpc(name = "cfx_protocolVersion")]
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
    fn epoch_number(
        &self, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<RpcU256>;

    /// Returns balance of the given account.
    #[rpc(name = "cfx_getBalance")]
    fn balance(
        &self, addr: RpcH160, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<RpcU256>;

    /// Returns the code at given address at given time (epoch number).
    #[rpc(name = "cfx_getCode")]
    fn code(
        &self, addr: RpcH160, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Bytes>;

    //        /// Returns content of the storage at given address.
    //        #[rpc(name = "cfx_getStorageAt")]
    //        fn storage_at(&self, RpcH160, RpcU256, Option<BlockNumber>) ->
    // BoxFuture<RpcH256>;

    /// Returns block with given hash.
    #[rpc(name = "cfx_getBlockByHash")]
    fn block_by_hash(
        &self, block_hash: RpcH256, include_txs: bool,
    ) -> RpcResult<Option<Block>>;

    /// Returns block with given hash and pivot chain assumption.
    #[rpc(name = "cfx_getBlockByHashWithPivotAssumption")]
    fn block_by_hash_with_pivot_assumption(
        &self, block_hash: RpcH256, pivot_hash: RpcH256, epoch_number: RpcU64,
    ) -> RpcResult<Block>;

    /// Returns block with given epoch number.
    #[rpc(name = "cfx_getBlockByEpochNumber")]
    fn block_by_epoch_number(
        &self, epoch_number: EpochNumber, include_txs: bool,
    ) -> RpcResult<Block>;

    /// Returns best block hash.
    #[rpc(name = "cfx_getBestBlockHash")]
    fn best_block_hash(&self) -> RpcResult<RpcH256>;

    /// Returns the number of transactions sent from given address at given time
    /// (epoch number).
    #[rpc(name = "cfx_getTransactionCount")]
    fn transaction_count(
        &self, addr: RpcH160, epoch_number: Option<BlockHashOrEpochNumber>,
    ) -> RpcResult<RpcU256>;

    //        /// Returns the number of transactions in a block with given hash.
    //        #[rpc(name = "cfx_getBlockTransactionCountByHash")]
    //        fn block_transaction_count_by_hash(&self, RpcH256) ->
    // BoxFuture<Option<RpcU256>>;

    //        /// Returns the number of transactions in a block with given block
    // number.        #[rpc(name = "cfx_getBlockTransactionCountByNumber")]
    //        fn block_trasaction_count_by_number(&self, BlockNumber) ->
    // BoxFuture<Option<RpcU256>>;

    //        /// Returns the number of uncles in a block with given hash.
    //        #[rpc(name = "cfx_getUncleCountByBlockHash")]
    //        fn block_uncles_count_by_hash(&self, RpcH256) ->
    // BoxFuture<Option<RpcU256>>;

    //        /// Returns the number of uncles in a block with given block
    // number.        #[rpc(name = "cfx_getUnclesCountByBlockNumber")]
    //        fn block_uncles_count_by_number(&self, BlockNumber) ->
    // BoxFuture<Option<RpcU256>>;

    /// Sends signed transaction, returning its hash.
    #[rpc(name = "cfx_sendRawTransaction")]
    fn send_raw_transaction(&self, raw_tx: Bytes) -> RpcResult<RpcH256>;

    //        /// @alias of `cfx_sendRawTransaction`.
    //        #[rpc(name = "cfx_submitTransaction")]
    //        fn submit_transaction(&self, Bytes) -> RpcResult<RpcH256>;

    /// Call contract, returning the output data.
    #[rpc(name = "cfx_call")]
    fn call(
        &self, tx: RpcTransaction, epoch_number: Option<EpochNumber>,
    ) -> RpcResult<Bytes>;

    /// Returns logs matching the filter provided.
    #[rpc(name = "cfx_getLogs")]
    fn get_logs(&self, filter: RpcFilter) -> RpcResult<Vec<RpcLog>>;

    //        /// Estimate gas needed for execution of given contract.
    //        #[rpc(name = "cfx_estimateGas")]
    //        fn estimate_gas(&self, CallRequest, Option<BlockNumber>) ->
    // BoxFuture<RpcU256>;

    /// Get transaction by its hash.
    #[rpc(name = "cfx_getTransactionByHash")]
    fn transaction_by_hash(
        &self, tx_hash: RpcH256,
    ) -> RpcResult<Option<Transaction>>;

    #[rpc(name = "cfx_estimateGas")]
    fn estimate_gas(&self, tx: RpcTransaction) -> RpcResult<RpcU256>;

    #[rpc(name = "cfx_getBlocksByEpoch")]
    fn blocks_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<Vec<RpcH256>>;

    #[rpc(name = "cfx_getTransactionReceipt")]
    fn transaction_receipt(
        &self, tx_hash: RpcH256,
    ) -> RpcResult<Option<RpcReceipt>>;

    //        #[rpc(name = "cfx_getAccount")]
    //        fn account(&self, RpcH160, bool, RpcU64, Option<EpochNumber>) ->
    // RpcResult<Account>;

    //        /// Returns transaction at given block hash and index.
    //        #[rpc(name = "cfx_getTransactionByBlockHashAndIndex")]
    //        fn transaction_by_block_hash_and_index(&self, RpcH256, Index) ->
    // BoxFuture<Option<Transaction>>;

    //        /// Returns transaction by given block number and index.
    //        #[rpc(name = "cfx_getTransactionByBlockNumberAndIndex")]
    //        fn transaction_by_block_number_and_index(&self, BlockNumber,
    // Index) -> BoxFuture<Option<Transaction>>;

    //        /// Returns uncles at given block and index.
    //        #[rpc(name = "cfx_getUnclesByBlockHashAndIndex")]
    //        fn uncles_by_block_hash_and_index(&self, RpcH256, Index) ->
    // BoxFuture<Option<Block>>;

    //        /// Returns uncles at given block and index.
    //        #[rpc(name = "cfx_getUnclesByBlockNumberAndIndex")]
    //        fn uncles_by_block_number_and_index(&self, BlockNumber, Index) ->
    // BoxFuture<Option<Block>>;
}
