// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    types::pos::{
        Account, Block, BlockNumber, BlockTransactions, Decision, Signature,
        Status,
    },
    Pos,
};
use cfx_types::{hexstr_to_h256, H256, U64};
use cfxcore::consensus::pos_handler::PosVerifier;
use diem_crypto::hash::HashValue;
use diem_types::account_address::AccountAddress;
use diemdb::DiemDB;
use jsonrpc_core::Result as JsonRpcResult;
use std::sync::Arc;
use storage_interface::{DBReaderForPoW, DbReader};

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
            epoch: U64::from(epoch_state.epoch),
            block_number: U64::from(block_number),
            catch_up_mode: state.catch_up_mode(),
            pivot_decision: Decision::from(decision.clone()),
        }
    }

    fn account_impl(&self, address: H256, view: U64) -> Option<Account> {
        /*let state = self.diem_db.get_latest_pos_state();
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
        }*/
        None
    }

    fn block_by_hash_impl(&self, hash: H256) -> Option<Block> {
        let hash_value = HashValue::from_slice(hash.as_bytes()).unwrap();
        let block = self.diem_db.get_committed_block(&hash_value);

        match block {
            Ok(b) => {
                let signatures = b
                    .signatures
                    .iter()
                    .map(|(a, s)| Signature {
                        account: H256::from(a.to_u8()),
                        signature: s.to_string(),
                    })
                    .collect();
                Some(Block {
                    hash,
                    height: Default::default(), // TODO
                    epoch: U64::from(b.epoch),
                    round: U64::from(b.round),
                    version: U64::from(b.version),
                    miner: H256::from(b.miner.to_u8()),
                    parent_hash: hexstr_to_h256(
                        b.parent_hash.to_hex().as_str(),
                    ),
                    timestamp: U64::from(b.timestamp),
                    pivot_decision: Some(Decision::from(b.pivot_decision)),
                    transactions: BlockTransactions::Hashes(vec![]), // TODO
                    signatures,
                })
            }
            Err(_) => None,
        }
    }

    fn block_by_number_impl(&self, number: BlockNumber) -> Option<Block> {
        match number {
            BlockNumber::Num(num) => {
                println!("{}", num);
                None
            }
            BlockNumber::Earliest => None,
            BlockNumber::Latest => {
                let latest_ledger =
                    self.diem_db.get_latest_ledger_info_option().unwrap();
                let ledger_info = latest_ledger.ledger_info();
                let pivot_decision = ledger_info
                    .pivot_decision()
                    .map(|p| Decision::from(p.clone()));
                let signatures = latest_ledger
                    .signatures()
                    .iter()
                    .map(|(a, s)| Signature {
                        account: H256::from(a.to_u8()),
                        signature: s.to_string(),
                    })
                    .collect();
                let block = Block {
                    hash: hexstr_to_h256(
                        ledger_info.consensus_block_id().to_hex().as_str(),
                    ),
                    height: Default::default(), // TODO
                    epoch: U64::from(ledger_info.epoch()),
                    round: U64::from(ledger_info.round()),
                    version: U64::from(ledger_info.version()),
                    miner: Default::default(), // TODO
                    parent_hash: Default::default(), // TODO
                    timestamp: U64::from(ledger_info.timestamp_usecs()),
                    pivot_decision,
                    transactions: BlockTransactions::Hashes(vec![]), // TODO
                    signatures,
                };
                Some(block)
            }
        }
    }
}

impl Pos for PosHandler {
    fn pos_status(&self) -> JsonRpcResult<Status> { Ok(self.status_impl()) }

    fn pos_block_by_hash(&self, hash: H256) -> JsonRpcResult<Option<Block>> {
        Ok(self.block_by_hash_impl(hash))
    }

    fn pos_block_by_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<Block>> {
        Ok(self.block_by_number_impl(number))
    }

    fn pos_account(
        &self, address: H256, view: U64,
    ) -> JsonRpcResult<Option<Account>> {
        Ok(self.account_impl(address, view))
    }
}
