// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Eth rpc interface.
use crate::rpc::types::U64 as HexU64;
use cfx_types::{H160, H256, U256, U64};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use crate::rpc::types::{
    eth::{
        AccountPendingTransactions, Block, BlockNumber, BlockOverrides,
        EthRpcLogFilter, Log, Receipt, RpcStateOverride, SyncStatus,
        Transaction, TransactionRequest,
    },
    Bytes, FeeHistory, Index,
};

/// Eth rpc interface.
#[rpc(server)]
pub trait Eth {
    #[rpc(name = "web3_clientVersion")]
    fn client_version(&self) -> Result<String>;

    #[rpc(name = "net_version")]
    fn net_version(&self) -> Result<String>;

    /// Returns protocol version encoded as a string (quotes are necessary).
    #[rpc(name = "eth_protocolVersion")]
    fn protocol_version(&self) -> Result<String>;

    /// Returns an object with data about the sync status or false. (wtf?)
    #[rpc(name = "eth_syncing")]
    fn syncing(&self) -> Result<SyncStatus>;

    /// Returns the number of hashes per second that the node is mining with.
    #[rpc(name = "eth_hashrate")]
    fn hashrate(&self) -> Result<U256>;

    /// Returns block author.
    #[rpc(name = "eth_coinbase")]
    fn author(&self) -> Result<H160>;

    /// Returns true if client is actively mining new blocks.
    #[rpc(name = "eth_mining")]
    fn is_mining(&self) -> Result<bool>;

    /// Returns the chain ID used for transaction signing at the
    /// current best block. None is returned if not
    /// available.
    #[rpc(name = "eth_chainId")]
    fn chain_id(&self) -> Result<Option<U64>>;

    /// Returns current gas_price.
    #[rpc(name = "eth_gasPrice")]
    fn gas_price(&self) -> Result<U256>;

    /// Returns current max_priority_fee
    #[rpc(name = "eth_maxPriorityFeePerGas")]
    fn max_priority_fee_per_gas(&self) -> Result<U256>;

    #[rpc(name = "eth_feeHistory")]
    fn fee_history(
        &self, block_count: HexU64, newest_block: BlockNumber,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<FeeHistory>;

    /// Returns accounts list.
    #[rpc(name = "eth_accounts")]
    fn accounts(&self) -> Result<Vec<H160>>;

    /// Returns highest block number.
    #[rpc(name = "eth_blockNumber")]
    fn block_number(&self) -> Result<U256>;

    /// Returns balance of the given account.
    #[rpc(name = "eth_getBalance")]
    fn balance(
        &self, address: H160, block: Option<BlockNumber>,
    ) -> Result<U256>;

    /// Returns content of the storage at given address.
    #[rpc(name = "eth_getStorageAt")]
    fn storage_at(
        &self, address: H160, storage_slot: U256, block: Option<BlockNumber>,
    ) -> jsonrpc_core::Result<H256>;

    /// Returns block with given hash.
    #[rpc(name = "eth_getBlockByHash")]
    fn block_by_hash(
        &self, block_hash: H256, hydrated_transactions: bool,
    ) -> Result<Option<Block>>;

    /// Returns block with given number.
    #[rpc(name = "eth_getBlockByNumber")]
    fn block_by_number(
        &self, block: BlockNumber, hydrated_transactions: bool,
    ) -> Result<Option<Block>>;

    /// Returns the number of transactions sent from given address at given time
    /// (block number).
    #[rpc(name = "eth_getTransactionCount")]
    fn transaction_count(
        &self, address: H160, block: Option<BlockNumber>,
    ) -> Result<U256>;

    /// Returns the number of transactions in a block with given hash.
    #[rpc(name = "eth_getBlockTransactionCountByHash")]
    fn block_transaction_count_by_hash(
        &self, block_hash: H256,
    ) -> Result<Option<U256>>;

    /// Returns the number of transactions in a block with given block number.
    #[rpc(name = "eth_getBlockTransactionCountByNumber")]
    fn block_transaction_count_by_number(
        &self, block: BlockNumber,
    ) -> Result<Option<U256>>;

    /// Returns the number of uncles in a block with given hash.
    #[rpc(name = "eth_getUncleCountByBlockHash")]
    fn block_uncles_count_by_hash(
        &self, block_hash: H256,
    ) -> Result<Option<U256>>;

    /// Returns the number of uncles in a block with given block number.
    #[rpc(name = "eth_getUncleCountByBlockNumber")]
    fn block_uncles_count_by_number(
        &self, block: BlockNumber,
    ) -> Result<Option<U256>>;

    /// Returns the code at given address at given time (block number).
    #[rpc(name = "eth_getCode")]
    fn code_at(
        &self, address: H160, block: Option<BlockNumber>,
    ) -> Result<Bytes>;

    /// Sends signed transaction, returning its hash.
    #[rpc(name = "eth_sendRawTransaction")]
    fn send_raw_transaction(&self, transaction: Bytes) -> Result<H256>;

    /// @alias of `eth_sendRawTransaction`.
    #[rpc(name = "eth_submitTransaction")]
    fn submit_transaction(&self, transaction: Bytes) -> Result<H256>;

    /// Call contract, returning the output data.
    /// TODO support state_overrides and block_overrides
    #[rpc(name = "eth_call")]
    fn call(
        &self, transaction: TransactionRequest, block: Option<BlockNumber>,
        state_overrides: Option<RpcStateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> Result<Bytes>;

    /// Estimate gas needed for execution of given contract.
    #[rpc(name = "eth_estimateGas")]
    fn estimate_gas(
        &self, transaction: TransactionRequest, block: Option<BlockNumber>,
        state_override: Option<RpcStateOverride>,
    ) -> Result<U256>;

    /// Get transaction by its hash.
    #[rpc(name = "eth_getTransactionByHash")]
    fn transaction_by_hash(
        &self, transaction_hash: H256,
    ) -> Result<Option<Transaction>>;

    /// Returns transaction at given block hash and index.
    #[rpc(name = "eth_getTransactionByBlockHashAndIndex")]
    fn transaction_by_block_hash_and_index(
        &self, block_hash: H256, transaction_index: Index,
    ) -> Result<Option<Transaction>>;

    /// Returns transaction by given block number and index.
    #[rpc(name = "eth_getTransactionByBlockNumberAndIndex")]
    fn transaction_by_block_number_and_index(
        &self, block: BlockNumber, transaction_index: Index,
    ) -> Result<Option<Transaction>>;

    /// Returns transaction receipt by transaction hash.
    #[rpc(name = "eth_getTransactionReceipt")]
    fn transaction_receipt(
        &self, transaction_hash: H256,
    ) -> Result<Option<Receipt>>;

    /// Returns an uncles at given block and index.
    #[rpc(name = "eth_getUncleByBlockHashAndIndex")]
    fn uncle_by_block_hash_and_index(
        &self, block_hash: H256, _: Index,
    ) -> Result<Option<Block>>;

    /// Returns an uncles at given block and index.
    #[rpc(name = "eth_getUncleByBlockNumberAndIndex")]
    fn uncle_by_block_number_and_index(
        &self, block: BlockNumber, _: Index,
    ) -> Result<Option<Block>>;

    /// Returns logs matching given filter object.
    #[rpc(name = "eth_getLogs")]
    fn logs(&self, filter: EthRpcLogFilter) -> Result<Vec<Log>>;

    /// Used for submitting mining hashrate.
    #[rpc(name = "eth_submitHashrate")]
    fn submit_hashrate(&self, _: U256, _: H256) -> Result<bool>;

    #[rpc(name = "eth_getBlockReceipts")]
    fn eth_block_receipts(&self, block: BlockNumber) -> Result<Vec<Receipt>>;

    #[rpc(name = "parity_getBlockReceipts")]
    fn block_receipts(
        &self, block: Option<BlockNumber>,
    ) -> Result<Vec<Receipt>>;

    #[rpc(name = "eth_getAccountPendingTransactions")]
    fn account_pending_transactions(
        &self, address: H160, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> Result<AccountPendingTransactions>;
}
