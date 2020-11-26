// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::traits::trace::Trace;
use jsonrpc_core::{Result as JsonRpcResult};
use cfx_types::H256;
use super::super::types::LocalizedBlockTrace;
use std::sync::Arc;
use cfxcore::BlockDataManager;

pub struct TraceHandler {
    data_man: Arc<BlockDataManager>,
}

impl TraceHandler {
    pub fn new(data_man: Arc<BlockDataManager>) -> Self {
        TraceHandler {
            data_man
        }
    }
}

impl Trace for TraceHandler {
    fn block_traces(&self, block_hash: H256) -> JsonRpcResult<Option<LocalizedBlockTrace>> {
        Ok(self.data_man.block_traces_by_hash(&block_hash).map(Into::into))
    }
}