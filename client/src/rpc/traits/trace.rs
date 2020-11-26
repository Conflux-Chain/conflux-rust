// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use jsonrpc_core::{Result as JsonRpcResult};
use jsonrpc_derive::rpc;
use cfx_types::H256;
use super::super::types::LocalizedBlockTrace;

/// Trace specific rpc interface.
#[rpc(server)]
pub trait Trace {
     /// Returns all traces produced at given block.
     #[rpc(name = "trace_block")]
     fn block_traces(&self, block_hash: H256) -> JsonRpcResult<Option<LocalizedBlockTrace>>;
}