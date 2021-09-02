// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::traits::pos::Pos;
use jsonrpc_core::Result as JsonRpcResult;
use crate::rpc::types::pos::{Status, Account};
// use crate::common::delegate_convert::into_jsonrpc_result;
use diemdb::DiemDB;
use std::sync::Arc;
use storage_interface::DbReader;
use cfxcore::consensus::pos_handler::PosVerifier;
use cfx_types::{H256, U64};
use diem_types::account_address::AccountAddress;

pub struct PosHandler {
    diem_db: Arc<DiemDB>,
    pos_handler: Arc<PosVerifier>,
}

impl PosHandler {
    pub fn new(diem_db: Arc<DiemDB>, pos_verifier: Arc<PosVerifier>) -> Self {
        PosHandler {
            diem_db,
            pos_handler: pos_verifier,
        }
    }

    fn status_impl(&self) -> Status {
        let state = self.diem_db.get_latest_pos_state();
        let decision = state.pivot_decision();
        let epoch_state = state.epoch_state();
        let block_number = state.current_view();
        Status {
            chain_id: 1,  // TODO find the chain_id
            epoch: epoch_state.epoch,
            block_number,
            catch_up_mode: state.catch_up_mode(),
            pivot_decision: decision.clone(),
        }
    }

    fn account_impl(&self, address: H256, view: U64) -> Option<Account> {
        let state = self.diem_db.get_latest_pos_state();
        let account_address = AccountAddress::from_hex(address);

        if let Ok(a) = account_address {
            let maybe_node_data = state.account_node_data(a);

            if let Some(node_data) = maybe_node_data {
                return Some(Account {
                    address,
                    status: node_data.status(),
                    status_start_view: U64::from(node_data.status_start_view()),
                    voting_power: U64::from(node_data.voting_power()),
                });
            };
        }
        None
    }
}

impl Pos for PosHandler {
    fn pos_status(&self) -> JsonRpcResult<Status> {
        let status = self.status_impl();
        Ok(status)
        // into_jsonrpc_result(Ok(status))
    }

    fn pos_account(&self, address: H256, view: U64) -> JsonRpcResult<Option<Account>> {
        Ok(self.account_impl(address, view))
    }
}