// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::delegate_convert,
    rpc::{
        impls::common::RpcImpl as CommonImpl,
        traits::pool::TransactionPool,
        types::{
            AccountPendingInfo, AccountPendingTransactions, RpcAddress,
            Transaction as RpcTransaction, TxPoolPendingNonceRange,
            TxPoolStatus, TxWithPoolInfo,
        },
    },
};
use cfx_types::{H256, U256, U64};
use delegate::delegate;
use jsonrpc_core::{BoxFuture, Result as JsonRpcResult};
use std::sync::Arc;

pub struct TransactionPoolHandler {
    common: Arc<CommonImpl>,
}

impl TransactionPoolHandler {
    pub fn new(common: Arc<CommonImpl>) -> Self {
        TransactionPoolHandler { common }
    }
}

impl TransactionPool for TransactionPoolHandler {
    delegate! {
        to self.common {
            fn txpool_status(&self) -> JsonRpcResult<TxPoolStatus>;
            fn txpool_next_nonce(&self, address: RpcAddress) -> JsonRpcResult<U256>;
            fn txpool_pending_nonce_range(&self, address: RpcAddress) -> JsonRpcResult<TxPoolPendingNonceRange>;
            fn txpool_tx_with_pool_info(&self, hash: H256) -> JsonRpcResult<TxWithPoolInfo>;
            fn txpool_transaction_by_address_and_nonce(&self, address: RpcAddress, nonce: U256) -> JsonRpcResult<Option<RpcTransaction>>;
            fn account_pending_info(&self, addr: RpcAddress) -> BoxFuture<JsonRpcResult<Option<AccountPendingInfo>>>;
            fn account_pending_transactions(&self, address: RpcAddress, maybe_start_nonce: Option<U256>, maybe_limit: Option<U64>) -> BoxFuture<JsonRpcResult<AccountPendingTransactions>>;
        }
    }
}
