// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        traits::pos::Pos,
        types::pos::{
            Account, Block, BlockNumber, BlockTransactions, CommitteeState,
            NodeLockStatus, RpcCommittee, RpcTermData, Signature, Status,
            Transaction,
        },
        RpcResult,
    },
};
use cfx_types::{hexstr_to_h256, H256, U64};
use cfxcore::consensus::pos_handler::PosVerifier;
use consensus_types::block::Block as ConsensusBlock;
use diem_crypto::hash::HashValue;
use diem_types::{
    account_address::AccountAddress,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    term_state::{lock_status::StatusList, PosState, TERM_LIST_LEN},
    transaction::{Transaction as CoreTransaction, TransactionStatus},
};
use itertools::Itertools;
use jsonrpc_core::Result as JsonRpcResult;
use std::sync::Arc;
use storage_interface::{DBReaderForPoW, DbReader};

pub struct PosHandler {
    pos_handler: Arc<PosVerifier>,
}

impl PosHandler {
    pub fn new(pos_verifier: Arc<PosVerifier>) -> Self {
        PosHandler {
            pos_handler: pos_verifier,
        }
    }

    fn current_height(&self) -> u64 {
        self.pos_handler
            .diem_db()
            .get_latest_pos_state()
            .current_view()
    }

    fn current_epoch(&self) -> u64 {
        self.pos_handler
            .diem_db()
            .get_latest_pos_state()
            .epoch_state()
            .epoch
    }

    fn status_impl(&self) -> Status {
        let state = self.pos_handler.diem_db().get_latest_pos_state();
        let decision = state.pivot_decision();
        let epoch_state = state.epoch_state();
        let block_number = state.current_view();
        let latest_voted = self
            .consensus_blocks()
            .unwrap_or(vec![])
            .last()
            .map(|b| U64::from(b.height));
        Status {
            epoch: U64::from(epoch_state.epoch),
            block_number: U64::from(block_number),
            pivot_decision: U64::from(decision.height),
            latest_voted,
        }
    }

    fn account_impl(
        &self, address: H256, view: Option<U64>,
    ) -> RpcResult<Account> {
        let state = self.pos_state_by_view(view)?;

        let account_address = AccountAddress::from_bytes(address);

        if let Ok(addr) = account_address {
            let maybe_node_data = state.account_node_data(addr);
            info!("maybe_node_data {:?}", maybe_node_data);

            if let Some(node_data) = maybe_node_data {
                let lock_status = node_data.lock_status();
                return Ok(Account {
                    address,
                    block_number: U64::from(state.current_view()),
                    status: NodeLockStatus {
                        in_queue: map_votes(&lock_status.in_queue),
                        locked: U64::from(lock_status.locked),
                        out_queue: map_votes(&lock_status.out_queue),
                        unlocked: U64::from(lock_status.unlocked()),
                        available_votes: U64::from(
                            lock_status.available_votes(),
                        ),
                        force_retired: lock_status.force_retired(),
                        exempt_from_forfeit: lock_status
                            .exempt_from_forfeit()
                            .map(U64::from),
                    },
                });
            };
        }

        let mut default_acct: Account = Account::default();
        default_acct.address = address;
        default_acct.block_number = U64::from(state.current_view());
        return Ok(default_acct);
    }

    fn pos_state_by_view(
        &self, view: Option<U64>,
    ) -> Result<Arc<PosState>, String> {
        let state = match view {
            None => self.pos_handler.diem_db().get_latest_pos_state(),
            Some(v) => {
                let latest_view = self.current_height();
                let v = v.as_u64();
                if v > latest_view {
                    bail!("Specified block {} is not executed, the latest block number is {}", v, latest_view)
                }

                let state = self
                    .pos_handler
                    .diem_db()
                    .get_committed_block_hash_by_view(v)
                    .and_then(|block_hash| {
                        self.pos_handler.diem_db().get_pos_state(&block_hash)
                    })
                    .map_err(|_| format!("PoS state of {} not found", v))?;
                Arc::new(state)
            }
        };
        Ok(state)
    }

    fn committee_by_block_number(
        &self, view: Option<U64>,
    ) -> RpcResult<CommitteeState> {
        let mut state = CommitteeState::default();
        let pos_state = self.pos_state_by_view(view)?;

        state.current_committee =
            RpcCommittee::from_epoch_state(pos_state.epoch_state());

        // get future term data
        let term_list = pos_state.term_list().term_list();
        for i in TERM_LIST_LEN..=TERM_LIST_LEN + 1 {
            if let Some(term_data) = term_list.get(i) {
                state.elections.push(RpcTermData::from(term_data))
            }
        }

        Ok(state)
    }

    // get epoch ending ledger info
    fn ledger_info_by_epoch(
        &self, epoch: u64,
    ) -> Option<LedgerInfoWithSignatures> {
        let epoch_change_proof = self
            .pos_handler
            .diem_db()
            .get_epoch_ending_ledger_infos(epoch, epoch)
            .ok()?;
        let ledger_infos = epoch_change_proof.get_all_ledger_infos();
        if ledger_infos.len() > 0 {
            Some(ledger_infos[0].clone())
        } else {
            None
        }
    }

    // get epoch state
    fn epoch_state_by_epoch_number(&self, epoch: u64) -> Option<EpochState> {
        if epoch == 0 {
            return None;
        }
        if epoch == self.current_epoch() {
            return Some(
                self.pos_handler
                    .diem_db()
                    .get_latest_pos_state()
                    .epoch_state()
                    .clone(),
            );
        }
        if let Some(ledger_info) = self.ledger_info_by_epoch(epoch - 1) {
            let option = ledger_info.ledger_info().next_epoch_state();
            return option.map(|f| (*f).clone());
        }
        None
    }

    fn block_by_hash(&self, hash: H256) -> Option<Block> {
        let hash_value = HashValue::from_slice(hash.as_bytes()).ok()?;
        let block = self
            .pos_handler
            .diem_db()
            .get_committed_block_by_hash(&hash_value);
        match block {
            Ok(b) => {
                let mut block = Block {
                    hash,
                    height: U64::from(b.view),
                    epoch: U64::from(b.epoch),
                    round: U64::from(b.round),
                    version: U64::from(b.version),
                    miner: b.miner.map(|m| H256::from(m.to_u8())),
                    parent_hash: hexstr_to_h256(
                        b.parent_hash.to_hex().as_str(),
                    ),
                    timestamp: U64::from(b.timestamp),
                    pivot_decision: Some(U64::from(b.pivot_decision.height)),
                    transactions: BlockTransactions::Hashes(vec![]), // TODO
                    signatures: vec![],
                };
                // get signatures info
                // TODO how to get epoch 1's votes info
                if let Some(epoch_state) =
                    self.epoch_state_by_epoch_number(b.epoch)
                {
                    let signatures = b
                        .signatures
                        .iter()
                        .map(|(a, _s)| {
                            let voting_power = epoch_state
                                .verifier
                                .get_voting_power(a)
                                .unwrap_or(0);
                            Signature {
                                account: H256::from(a.to_u8()),
                                // signature: s.to_string(),
                                votes: U64::from(voting_power),
                            }
                        })
                        .collect();
                    block.signatures = signatures;
                };
                Some(block)
            }
            Err(_) => self.consensus_block_hash(hash),
        }
    }

    fn block_by_number(&self, number: BlockNumber) -> Option<Block> {
        match number {
            BlockNumber::Num(num) => {
                if num.as_u64() <= self.current_height() {
                    let hash = self
                        .pos_handler
                        .diem_db()
                        .get_committed_block_hash_by_view(num.as_u64())
                        .ok()?;
                    self.block_by_hash(hexstr_to_h256(hash.to_hex().as_str()))
                } else {
                    self.consensus_block_number(num)
                }
            }
            BlockNumber::LatestCommitted => {
                let hash = self.pos_handler.get_latest_pos_reference();
                self.block_by_hash(hash)
            }
            BlockNumber::LatestVoted => {
                self.consensus_blocks()?.last().map(|b| (*b).clone())
            }
            BlockNumber::Earliest => None,
        }
    }

    fn consensus_blocks(&self) -> Option<Vec<Block>> {
        let blocks = self.pos_handler.consensus_db().get_blocks().ok()?;
        if blocks.len() == 0 {
            return Some(vec![]);
        }
        let qcs = self
            .pos_handler
            .consensus_db()
            .get_quorum_certificates()
            .ok()?;
        // sort by epoch and round
        let blocks: Vec<ConsensusBlock> = blocks
            .into_iter()
            .sorted_by(|(_, b1), (_, b2)| {
                Ord::cmp(&(b1.epoch(), b1.round()), &(b2.epoch(), b2.round()))
            })
            .map(|(_, b)| b)
            .collect();
        // find first block's height
        let committed_block = self
            .pos_handler
            .diem_db()
            .get_committed_block_by_hash(&blocks[0].id())
            .ok()?;
        let mut current_height = committed_block.view;
        let latest_epoch_state = self
            .pos_handler
            .diem_db()
            .get_latest_pos_state()
            .epoch_state()
            .clone();
        // map to Committed block
        let rpc_blocks = blocks
            .into_iter()
            .filter(|b| b.epoch() == latest_epoch_state.epoch)
            .map(|b| {
                let mut rpc_block = Block {
                    hash: hexstr_to_h256(b.id().to_hex().as_str()),
                    height: U64::from(current_height),
                    epoch: U64::from(b.epoch()),
                    round: U64::from(b.round()),
                    version: Default::default(),
                    miner: b.author().map(|a| H256::from(a.to_u8())),
                    parent_hash: hexstr_to_h256(
                        b.parent_id().to_hex().as_str(),
                    ),
                    timestamp: U64::from(b.timestamp_usecs()),
                    pivot_decision: Default::default(),
                    transactions: BlockTransactions::Hashes(vec![]), // TODO
                    signatures: vec![],
                };
                current_height += 1;
                if let Some(qc) = qcs.get(&b.id()) {
                    rpc_block.version = U64::from(qc.commit_info().version());
                    rpc_block.pivot_decision = qc
                        .commit_info()
                        .pivot_decision()
                        .map(|p| U64::from(p.height));
                    let signatures = qc
                        .ledger_info()
                        .signatures()
                        .iter()
                        .map(|(a, _s)| {
                            let voting_power = latest_epoch_state
                                .verifier
                                .get_voting_power(a)
                                .unwrap_or(0);
                            Signature {
                                account: H256::from(a.to_u8()),
                                // signature: s.to_string(),
                                votes: U64::from(voting_power),
                            }
                        })
                        .collect();
                    rpc_block.signatures = signatures;
                }
                rpc_block
            })
            .filter(|b| b.pivot_decision.is_some())
            .collect::<Vec<_>>();
        Some(rpc_blocks)
    }

    fn consensus_block_number(&self, number: U64) -> Option<Block> {
        self.consensus_blocks()?
            .into_iter()
            .find(|b| b.height == number)
    }

    fn consensus_block_hash(&self, hash: H256) -> Option<Block> {
        self.consensus_blocks()?
            .into_iter()
            .find(|b| b.hash == hash)
    }
}

fn map_votes(list: &StatusList) -> Vec<(U64, U64)> {
    let mut ans = Vec::with_capacity(list.len());
    for item in list.iter() {
        ans.push((U64::from(item.view), U64::from(item.votes)));
    }
    ans
}

impl Pos for PosHandler {
    fn pos_status(&self) -> JsonRpcResult<Status> { Ok(self.status_impl()) }

    fn pos_account(
        &self, address: H256, view: Option<U64>,
    ) -> JsonRpcResult<Account> {
        into_jsonrpc_result(self.account_impl(address, view))
    }

    fn pos_committee(
        &self, view: Option<U64>,
    ) -> JsonRpcResult<CommitteeState> {
        into_jsonrpc_result(self.committee_by_block_number(view))
    }

    fn pos_block_by_hash(&self, hash: H256) -> JsonRpcResult<Option<Block>> {
        Ok(self.block_by_hash(hash))
    }

    fn pos_block_by_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<Block>> {
        Ok(self.block_by_number(number))
    }

    fn pos_transaction_by_version(
        &self, version: U64,
    ) -> JsonRpcResult<Option<Transaction>> {
        let tx = self.pos_handler.diem_db().get_transaction(version.as_u64());
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

    fn pos_consensus_blocks(&self) -> JsonRpcResult<Vec<Block>> {
        Ok(self.consensus_blocks().unwrap_or(vec![]))
    }
}
