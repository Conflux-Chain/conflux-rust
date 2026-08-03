// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    AccountPendingInfo, AccountPendingTransactions, BlockHashOrEpochNumber,
    Bytes as RpcBytes, Receipt as RpcReceipt, RpcAddress, TransactionRequest,
};
use cfx_types::{H256, H520, U128, U256, U64};
use jsonrpsee::{core::RpcResult as JsonRpcResult, proc_macros::rpc};

#[rpc(server, namespace = "cfx")]
pub trait CfxDebugRpc {
    #[method(name = "sendTransaction")]
    async fn send_transaction(
        &self, tx: TransactionRequest, password: Option<String>,
    ) -> JsonRpcResult<H256>;

    /// Returns accounts list.
    #[method(name = "accounts")]
    async fn accounts(&self) -> JsonRpcResult<Vec<RpcAddress>>;

    /// Create a new account
    #[method(name = "newAccount")]
    async fn new_account(&self, password: String) -> JsonRpcResult<RpcAddress>;

    /// Unlock an account
    #[method(name = "unlockAccount")]
    async fn unlock_account(
        &self, address: RpcAddress, password: String, duration: Option<U128>,
    ) -> JsonRpcResult<bool>;

    /// Lock an account
    #[method(name = "lockAccount")]
    async fn lock_account(&self, address: RpcAddress) -> JsonRpcResult<bool>;

    #[method(name = "sign")]
    fn sign(
        &self, data: RpcBytes, address: RpcAddress, password: Option<String>,
    ) -> JsonRpcResult<H520>;

    #[method(name = "signTransaction")]
    fn sign_transaction(
        &self, tx: TransactionRequest, password: Option<String>,
    ) -> JsonRpcResult<String>;

    #[method(name = "getEpochReceipts")]
    async fn epoch_receipts(
        &self, epoch: BlockHashOrEpochNumber,
        include_eth_receipts: Option<bool>,
    ) -> JsonRpcResult<Option<Vec<Vec<RpcReceipt>>>>;

    /// Get transaction pending info by account address
    #[method(name = "getAccountPendingInfo")]
    async fn account_pending_info(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<Option<AccountPendingInfo>>;

    /// Get transaction pending info by account address
    #[method(name = "getAccountPendingTransactions")]
    async fn account_pending_transactions(
        &self, address: RpcAddress, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<U64>,
    ) -> JsonRpcResult<AccountPendingTransactions>;
}
