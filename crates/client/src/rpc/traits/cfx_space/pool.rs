// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    AccountPendingInfo, AccountPendingTransactions, RpcAddress,
    Transaction as RpcTransaction, TxPoolPendingNonceRange, TxPoolStatus,
    TxWithPoolInfo,
};
use cfx_types::{H256, U256, U64};
use jsonrpc_core::{BoxFuture, Result as JsonRpcResult};
use jsonrpc_derive::rpc;
/// Transaction pool RPCs
#[rpc(server)]
pub trait TransactionPool {
    #[rpc(name = "txpool_status")]
    fn txpool_status(&self) -> JsonRpcResult<TxPoolStatus>;

    #[rpc(name = "txpool_nextNonce")]
    fn txpool_next_nonce(&self, address: RpcAddress) -> JsonRpcResult<U256>;

    #[rpc(name = "txpool_transactionByAddressAndNonce")]
    fn txpool_transaction_by_address_and_nonce(
        &self, address: RpcAddress, nonce: U256,
    ) -> JsonRpcResult<Option<RpcTransaction>>;

    #[rpc(name = "txpool_pendingNonceRange")]
    fn txpool_pending_nonce_range(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<TxPoolPendingNonceRange>;

    #[rpc(name = "txpool_txWithPoolInfo")]
    fn txpool_tx_with_pool_info(
        &self, hash: H256,
    ) -> JsonRpcResult<TxWithPoolInfo>;

    /// Get transaction pending info by account address
    #[rpc(name = "txpool_accountPendingInfo")]
    fn account_pending_info(
        &self, address: RpcAddress,
    ) -> BoxFuture<JsonRpcResult<Option<AccountPendingInfo>>>;

    /// Get transaction pending info by account address
    #[rpc(name = "txpool_accountPendingTransactions")]
    fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> BoxFuture<JsonRpcResult<AccountPendingTransactions>>;
}
