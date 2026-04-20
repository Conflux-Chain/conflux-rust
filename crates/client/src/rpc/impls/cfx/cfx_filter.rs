// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_addr::Network;
use cfx_rpc_cfx_api::CfxFilterRpcServer;
use cfx_rpc_cfx_impl::CfxFilterHandler;
use cfx_rpc_utils::error::jsonrpc_error_helpers::error_object_owned_to_jsonrpc_error;
use cfx_types::{H128, H256};
use cfxcore::{channel::Channel, SharedConsensusGraph, SharedTransactionPool};
use jsonrpc_core::Result as JsonRpcResult;
use tokio::runtime::Runtime;

use crate::rpc::{
    traits::cfx_filter::CfxFilter,
    types::{CfxFilterChanges, CfxRpcLogFilter, Log},
};

/// Cfx filter rpc implementation for a full node.
pub struct CfxFilterClient {
    inner: CfxFilterHandler,
}

impl CfxFilterClient {
    /// Creates new Cfx filter client.
    pub fn new(
        consensus: SharedConsensusGraph, tx_pool: SharedTransactionPool,
        epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>, executor: Arc<Runtime>,
        poll_lifetime: u32, logs_filter_max_limit: Option<usize>,
        network: Network,
    ) -> Self {
        CfxFilterClient {
            inner: CfxFilterHandler::new(
                consensus,
                tx_pool,
                epochs_ordered,
                executor,
                poll_lifetime,
                logs_filter_max_limit,
                network,
            ),
        }
    }
}

impl CfxFilter for CfxFilterClient {
    fn new_filter(&self, filter: CfxRpcLogFilter) -> JsonRpcResult<H128> {
        self.inner
            .new_filter(filter)
            .map_err(error_object_owned_to_jsonrpc_error)
    }

    fn new_block_filter(&self) -> JsonRpcResult<H128> {
        self.inner
            .new_block_filter()
            .map_err(error_object_owned_to_jsonrpc_error)
    }

    fn new_pending_transaction_filter(&self) -> JsonRpcResult<H128> {
        self.inner
            .new_pending_transaction_filter()
            .map_err(error_object_owned_to_jsonrpc_error)
    }

    fn filter_changes(&self, index: H128) -> JsonRpcResult<CfxFilterChanges> {
        self.inner
            .filter_changes(index)
            .map_err(error_object_owned_to_jsonrpc_error)
    }

    fn filter_logs(&self, index: H128) -> JsonRpcResult<Vec<Log>> {
        self.inner
            .filter_logs(index)
            .map_err(error_object_owned_to_jsonrpc_error)
    }

    fn uninstall_filter(&self, index: H128) -> JsonRpcResult<bool> {
        self.inner
            .uninstall_filter(index)
            .map_err(error_object_owned_to_jsonrpc_error)
    }
}
