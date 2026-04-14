// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    AccountPendingInfo, AccountPendingTransactions, RpcAddress,
    Transaction as RpcTransaction, TxPoolPendingNonceRange, TxPoolStatus,
    TxWithPoolInfo,
};
use cfx_types::{H256, U256, U64};
use jsonrpsee::{core::RpcResult as JsonRpcResult, proc_macros::rpc};

/// Transaction pool RPCs
#[rpc(server, namespace = "txpool")]
pub trait TxPool {
    #[method(name = "status")]
    fn txpool_status(&self) -> JsonRpcResult<TxPoolStatus>;

    #[method(name = "nextNonce")]
    fn txpool_next_nonce(&self, address: RpcAddress) -> JsonRpcResult<U256>;

    #[method(name = "transactionByAddressAndNonce")]
    fn txpool_transaction_by_address_and_nonce(
        &self, address: RpcAddress, nonce: U256,
    ) -> JsonRpcResult<Option<RpcTransaction>>;

    #[method(name = "pendingNonceRange")]
    fn txpool_pending_nonce_range(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<TxPoolPendingNonceRange>;

    #[method(name = "txWithPoolInfo")]
    fn txpool_tx_with_pool_info(
        &self, hash: H256,
    ) -> JsonRpcResult<TxWithPoolInfo>;

    /// Get transaction pending info by account address
    #[method(name = "accountPendingInfo")]
    fn account_pending_info(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<Option<AccountPendingInfo>>;

    /// Get transaction pending info by account address
    #[method(name = "accountPendingTransactions")]
    fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> JsonRpcResult<AccountPendingTransactions>;
}
