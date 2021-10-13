// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    RpcAddress, Transaction as RpcTransaction, TxPoolPendingInfo, TxPoolStatus,
    TxWithPoolInfo,
};
use cfx_types::{H256, U256};
use jsonrpc_core::Result as JsonRpcResult;
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

    #[rpc(name = "txpool_accountTransactions")]
    fn txpool_get_account_transactions(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<Vec<RpcTransaction>>;

    #[rpc(name = "txpool_nonceRange")]
    fn txpool_nonce_range(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<TxPoolPendingInfo>;

    #[rpc(name = "txpool_txWithPoolInfo")]
    fn txpool_tx_with_pool_info(
        &self, hash: H256,
    ) -> JsonRpcResult<TxWithPoolInfo>;
}
