// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::pos::{Account, Status};
use cfx_types::{H256, U64};
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;

/// PoS specific rpc interface.
#[rpc(server)]
pub trait Pos {
    #[rpc(name = "pos_getStatus")]
    fn pos_status(&self) -> JsonRpcResult<Status>;

    #[rpc(name = "pos_getAccount")]
    fn pos_account(
        &self, address: H256, view: U64,
    ) -> JsonRpcResult<Option<Account>>;
}
