// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::delegate_convert,
    rpc::{
        impls::common::RpcImpl as CommonImpl,
        traits::TransactionPool,
        types::{
            RpcAddress, Transaction as RpcTransaction, TxPoolAccountInfo,
            TxPoolPendingInfo, TxWithPoolInfo,
        },
    },
};
use cfx_types::{H256, U256};
use delegate::delegate;
use jsonrpc_core::Result as JsonRpcResult;
use std::{collections::BTreeMap, sync::Arc};

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
            fn txpool_status(&self) -> JsonRpcResult<BTreeMap<String, usize>>;
            fn txpool_account_info(&self, address: RpcAddress) -> JsonRpcResult<TxPoolAccountInfo>;
            fn txpool_next_nonce(&self, address: RpcAddress, start_nonce: Option<U256>) -> JsonRpcResult<U256>;
            fn txpool_content(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<RpcTransaction>>>>>;
            fn txpool_inspect(&self, address: Option<RpcAddress>) -> JsonRpcResult<
                BTreeMap<String, BTreeMap<String, BTreeMap<usize, Vec<String>>>>>;
            fn tx_inspect_pending(&self, address: RpcAddress) -> JsonRpcResult<TxPoolPendingInfo>;
            fn tx_inspect(&self, hash: H256) -> JsonRpcResult<TxWithPoolInfo>;
            fn txs_from_pool(&self, address: Option<RpcAddress>) -> JsonRpcResult<Vec<RpcTransaction>>;
        }
    }
}
