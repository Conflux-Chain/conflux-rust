// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    traits::pos::Pos,
    types::pos::{
        Account, Block, BlockNumber, BlockTransactions, NodeLockStatus,
        Signature, Status, Transaction,
    },
};
use cfx_types::{hexstr_to_h256, H256, U64};
use cfxcore::consensus::pos_handler::PosVerifier;
use diem_crypto::hash::HashValue;
use diem_types::{
    account_address::AccountAddress,
    term_state::lock_status::StatusList,
    transaction::{Transaction as CoreTransaction, TransactionStatus},
};
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
            pivot_decision: U64::from(decision.height),
        }
    }

    fn account_impl(&self, address: H256, _view: U64) -> Account {
        let state = self.diem_db.get_latest_pos_state();
        let account_address = AccountAddress::from_hex(address);

        if let Ok(addr) = account_address {
            let maybe_node_data = state.account_node_data(addr);

            if let Some(node_data) = maybe_node_data {
                let lock_status = node_data.lock_status();
                return Account {
                    address,
                    block_number: U64::from(state.current_view()),
                    status: NodeLockStatus {
                        in_queue: sum_votes(&lock_status.in_queue),
                        locked: U64::from(lock_status.locked),
                        out_queue: sum_votes(&lock_status.out_queue),
                        unlocked: U64::from(lock_status.unlocked()),
                        available_votes: U64::from(
                            lock_status.available_votes(),
                        ),
                        force_retired: lock_status.force_retired(),
                        exempt_from_forfeit: lock_status
                            .exempt_from_forfeit()
                            .map(U64::from),
                    },
                };
            };
        }

        let mut default_acct: Account = Account::default();
        default_acct.address = address;
        default_acct.block_number = U64::from(state.current_view());
        return default_acct;
    }

    fn block_by_hash_impl(&self, hash: H256) -> Option<Block> {
        let hash_value = HashValue::from_slice(hash.as_bytes()).unwrap();
        let block = self.diem_db.get_committed_block_by_hash(&hash_value);
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
                    height: U64::from(b.view),
                    epoch: U64::from(b.epoch),
                    round: U64::from(b.round),
                    version: U64::from(b.version),
                    miner: H256::from(b.miner.to_u8()),
                    parent_hash: hexstr_to_h256(
                        b.parent_hash.to_hex().as_str(),
                    ),
                    timestamp: U64::from(b.timestamp),
                    pivot_decision: U64::from(b.pivot_decision.height),
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
                let hash =
                    self.diem_db.get_committed_block_hash_by_view(num.as_u64());
                match hash {
                    Ok(h) => self.block_by_hash_impl(hexstr_to_h256(
                        h.to_hex().as_str(),
                    )),
                    Err(_) => None,
                }
            }
            BlockNumber::Earliest => None,
            BlockNumber::Latest => {
                let hash = self.pos_handler.get_latest_pos_reference();
                self.block_by_hash_impl(hash)
            }
        }
    }
}

fn sum_votes(list: &StatusList) -> U64 {
    let mut sum: u64 = 0;
    for item in list.iter() {
        sum += item.votes;
    }
    U64::from(sum)
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

    fn pos_account(&self, address: H256, view: U64) -> JsonRpcResult<Account> {
        Ok(self.account_impl(address, view))
    }

    fn pos_transaction_by_version(
        &self, version: U64,
    ) -> JsonRpcResult<Option<Transaction>> {
        let tx = self.diem_db.get_transaction(version.as_u64());
        match tx {
            Ok(CoreTransaction::UserTransaction(signed_tx)) => {
                Ok(Some(Transaction {
                    hash: hexstr_to_h256(signed_tx.hash().to_hex().as_str()),
                    from: H256::from(signed_tx.sender().to_u8()),
                    version,
                    payload: signed_tx.payload().clone(),
                    status: TransactionStatus::Retry, // TODO
                }))
            }
            _ => Ok(None),
        }
    }
}
