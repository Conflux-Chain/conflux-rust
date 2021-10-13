// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    RpcAddress, Transaction as RpcTransaction, TxPoolAccountInfo,
    TxPoolPendingInfo, TxWithPoolInfo,
};
use cfx_types::{H256, U256};
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;
use std::collections::BTreeMap;

/// Transaction pool RPCs
#[rpc(server)]
pub trait TransactionPool {
    #[rpc(name = "txpool_status")]
    fn txpool_status(&self) -> JsonRpcResult<BTreeMap<String, usize>>;

    #[rpc(name = "txpool_accountInfo")]
    fn txpool_account_info(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<TxPoolAccountInfo>;

    #[rpc(name = "txpool_nextNonce")]
    fn txpool_next_nonce(
        &self, address: RpcAddress, start_nonce: Option<U256>,
    ) -> JsonRpcResult<U256>;

    #[rpc(name = "txpool_inspect")]
    fn txpool_inspect(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>,
    >;

    #[rpc(name = "txpool_content")]
    fn txpool_content(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<
        BTreeMap<
            String,
            BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>,
        >,
    >;

    #[rpc(name = "tx_inspect_pending")]
    fn tx_inspect_pending(
        &self, address: RpcAddress,
    ) -> JsonRpcResult<TxPoolPendingInfo>;

    #[rpc(name = "tx_inspect")]
    fn tx_inspect(&self, hash: H256) -> JsonRpcResult<TxWithPoolInfo>;

    #[rpc(name = "getTransactionsFromPool")]
    fn txs_from_pool(
        &self, address: Option<RpcAddress>,
    ) -> JsonRpcResult<Vec<RpcTransaction>>;
}
