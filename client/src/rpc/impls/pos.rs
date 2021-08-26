// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::traits::pos::Pos;
use jsonrpc_core::Result as JsonRpcResult;
use crate::rpc::types::pos::Status;
use crate::common::delegate_convert::into_jsonrpc_result;

pub struct PosHandler {

}

impl PosHandler {
    pub fn new() -> Self {
        PosHandler{}
    }
}

impl Pos for PosHandler {

    fn pos_status(&self) -> JsonRpcResult<Status> {
        let status = Default::default();
        into_jsonrpc_result(Ok(status))
    }
}