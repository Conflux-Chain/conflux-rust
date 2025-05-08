// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::delegate_convert::into_jsonrpc_result,
    rpc::{
        errors::{build_rpc_server_error, codes::POS_NOT_ENABLED},
        traits::pos::Pos,
        types::{
            pos::{
                tx_type, Account, Block, BlockNumber, CommitteeState, Decision,
                EpochState as RpcEpochState,
                LedgerInfoWithSignatures as RpcLedgerInfoWithSignatures,
                NodeLockStatus, PoSEpochReward, Reward, RpcCommittee,
                RpcTermData, RpcTransactionStatus, RpcTransactionType,
                Signature, Status, Transaction, VotePowerState,
            },
            EpochNumber, RpcAddress,
        },
        CoreResult, RpcInterceptor,
    },
};
use cfx_addr::Network;
use cfx_executor::internal_contract;
use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
use cfx_statedb::StateDbExt;
use cfx_types::{hexstr_to_h256, BigEndianHash, H256, U256, U64};
use cfx_util_macros::bail;
use cfxcore::{
    block_data_manager::block_data_types::PosRewardInfo,
    consensus::pos_handler::PosVerifier, BlockDataManager,
    SharedConsensusGraph,
};
use consensus_types::block::Block as ConsensusBlock;
use diem_crypto::hash::HashValue;
use diem_types::{
    account_address::AccountAddress,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    term_state::{lock_status::StatusList, PosState, TERM_LIST_LEN},
    transaction::Transaction as CoreTransaction,
};
use itertools::Itertools;
use jsonrpc_core::Result as JsonRpcResult;
use log::{debug, info};
use primitives::{StorageKey, StorageValue};
use std::{collections::HashMap, sync::Arc};
use storage_interface::{DBReaderForPoW, DbReader};

pub struct PoSInterceptor {
    pos_handler: Arc<PosVerifier>,
}

impl PoSInterceptor {
    pub fn new(pos_handler: Arc<PosVerifier>) -> Self {
        PoSInterceptor { pos_handler }
    }
}

impl RpcInterceptor for PoSInterceptor {
    fn before(&self, _name: &String) -> JsonRpcResult<()> {
        match self.pos_handler.pos_option() {
            Some(_) => Ok(()),
            None => bail!(build_rpc_server_error(
                POS_NOT_ENABLED,
                "PoS chain is not enabled".into()
            )),
        }
    }
}

pub struct PosHandler {
    pos_handler: Arc<PosVerifier>,
    pow_data_manager: Arc<BlockDataManager>,
    network_type: Network,
    consensus: SharedConsensusGraph,
}

impl PosHandler {
    pub fn new(
        pos_handler: Arc<PosVerifier>, pow_data_manager: Arc<BlockDataManager>,
        network_type: Network, consensus: SharedConsensusGraph,
    ) -> Self {
        PosHandler {
            pos_handler,
            pow_data_manager,
            network_type,
            consensus,
        }
    }

    fn current_height(&self) -> u64 {
        self.pos_handler
            .pos_ledger_db()
            .get_latest_pos_state()
            .current_view()
    }

    fn current_epoch(&self) -> u64 {
        self.pos_handler
            .pos_ledger_db()
            .get_latest_pos_state()
            .epoch_state()
            .epoch
    }

    fn status_impl(&self) -> Status {
        let state = self.pos_handler.pos_ledger_db().get_latest_pos_state();
        let decision = state.pivot_decision();
        let epoch_state = state.epoch_state();
        let block_number = state.current_view();
        let latest_voted = self.latest_voted().map(|b| U64::from(b.height));
        let latest_tx_number = self
            .block_by_number(BlockNumber::Num(U64::from(block_number)))
            .map(|b| b.last_tx_number.into())
            .unwrap_or_default();
        Status {
            epoch: U64::from(epoch_state.epoch),
            latest_committed: U64::from(block_number),
            pivot_decision: Decision::from(decision),
            latest_voted,
            latest_tx_number,
        }
    }

    fn account_impl(
        &self, address: H256, view: Option<U64>,
    ) -> CoreResult<Account> {
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
                        unlocked: U64::from(lock_status.unlocked_votes()),
                        available_votes: U64::from(
                            lock_status.available_votes(),
                        ),
                        force_retired: lock_status
                            .force_retired()
                            .map(|x| U64::from(x)),
                        forfeited: U64::from(lock_status.forfeited()),
                    },
                });
            };
        }

        let mut default_acct: Account = Account::default();
        default_acct.address = address;
        default_acct.block_number = U64::from(state.current_view());
        return Ok(default_acct);
    }

    fn account_by_pow_address_impl(
        &self, address: RpcAddress, view: Option<U64>,
    ) -> CoreResult<Account> {
        debug!(
            "Get pos account by pow address {:?}, view {:?}",
            address, view
        );

        let state_db = self.consensus.get_state_db_by_epoch_number(
            EpochNumber::LatestState.into(),
            "view",
        )?;

        let identifier_entry =
            internal_contract::pos_internal_entries::identifier_entry(
                &address.hex_address,
            );
        let storage_key = StorageKey::new_storage_key(
            &POS_REGISTER_CONTRACT_ADDRESS,
            identifier_entry.as_ref(),
        )
        .with_native_space();
        let StorageValue { value, .. } = state_db
            .get::<StorageValue>(storage_key)?
            .unwrap_or_default();
        let addr = BigEndianHash::from_uint(&value);

        debug!("Pos Address: {:?}", addr);

        self.account_impl(addr, view)
    }

    fn pos_state_by_view(
        &self, view: Option<U64>,
    ) -> Result<Arc<PosState>, String> {
        let latest_state =
            self.pos_handler.pos_ledger_db().get_latest_pos_state();
        let state = match view {
            None => latest_state,
            Some(v) => {
                let latest_view = latest_state.current_view();
                let v = v.as_u64();
                if v > latest_view {
                    bail!("Specified block {} is not executed, the latest block number is {}", v, latest_view)
                }

                let state = self
                    .pos_handler
                    .pos_ledger_db()
                    .get_committed_block_hash_by_view(v)
                    .and_then(|block_hash| {
                        self.pos_handler
                            .pos_ledger_db()
                            .get_pos_state(&block_hash)
                    })
                    .map_err(|_| format!("PoS state of {} not found", v))?;
                Arc::new(state)
            }
        };
        Ok(state)
    }

    fn committee_by_block_number(
        &self, view: Option<U64>,
    ) -> CoreResult<CommitteeState> {
        let pos_state = self.pos_state_by_view(view)?;

        let current_committee =
            RpcCommittee::from_epoch_state(pos_state.epoch_state());

        // get future term data
        let elections = pos_state.term_list().term_list()
            [TERM_LIST_LEN..=TERM_LIST_LEN + 1]
            .iter()
            .map(|term_data| RpcTermData::from(term_data))
            .collect();

        Ok(CommitteeState {
            current_committee,
            elections,
        })
    }

    // get epoch ending ledger info
    fn ledger_info_by_epoch(
        &self, epoch: u64,
    ) -> Option<LedgerInfoWithSignatures> {
        self.pos_handler
            .pos_ledger_db()
            .get_epoch_ending_ledger_infos(epoch, epoch + 1)
            .ok()?
            .get_all_ledger_infos()
            .first()
            .map(|l| l.clone())
    }

    fn ledger_infos_by_epoch(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Vec<LedgerInfoWithSignatures> {
        self.pos_handler
            .pos_ledger_db()
            .get_epoch_ending_ledger_infos(start_epoch, end_epoch)
            .ok()
            .map(|proof| proof.get_all_ledger_infos())
            .unwrap_or(vec![])
    }

    // get epoch state
    fn epoch_state_by_epoch_number(&self, epoch: u64) -> Option<EpochState> {
        if epoch == 0 {
            return None;
        }
        if epoch == self.current_epoch() {
            return Some(
                self.pos_handler
                    .pos_ledger_db()
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
            .pos_ledger_db()
            .get_committed_block_by_hash(&hash_value);
        match block {
            Ok(b) => {
                let mut block = Block {
                    hash,
                    height: U64::from(b.view),
                    epoch: U64::from(b.epoch),
                    round: U64::from(b.round),
                    last_tx_number: U64::from(b.version),
                    miner: b.miner.map(|m| H256::from(m.to_u8())),
                    parent_hash: hash_value_to_h256(b.parent_hash),
                    timestamp: U64::from(b.timestamp),
                    pivot_decision: Some(Decision::from(&b.pivot_decision)),
                    signatures: vec![],
                };
                // get signatures info
                if let Some(epoch_state) =
                    self.epoch_state_by_epoch_number(b.epoch)
                {
                    if let Ok(ledger_info) = self
                        .pos_handler
                        .pos_ledger_db()
                        .get_ledger_info_by_voted_block(&b.hash)
                    {
                        block.signatures = ledger_info
                            .signatures()
                            .iter()
                            .map(|(a, _s)| {
                                let voting_power = epoch_state
                                    .verifier()
                                    .get_voting_power(a)
                                    .unwrap_or(0);
                                Signature {
                                    account: H256::from(a.to_u8()),
                                    // signature: s.to_string(),
                                    votes: U64::from(voting_power),
                                }
                            })
                            .collect();
                    }
                };
                Some(block)
            }
            Err(_) => self.consensus_block_by_hash(hash),
        }
    }

    fn block_by_number(&self, number: BlockNumber) -> Option<Block> {
        match number {
            BlockNumber::Num(num) => {
                if num.as_u64() <= self.current_height() {
                    let hash = self
                        .pos_handler
                        .pos_ledger_db()
                        .get_committed_block_hash_by_view(num.as_u64())
                        .ok()?;
                    self.block_by_hash(hash_value_to_h256(hash))
                } else {
                    self.consensus_block_by_number(num)
                }
            }
            BlockNumber::LatestCommitted => {
                let hash = self.pos_handler.get_latest_pos_reference();
                self.block_by_hash(hash)
            }
            BlockNumber::Earliest => {
                let hash = self
                    .pos_handler
                    .pos_ledger_db()
                    .get_committed_block_hash_by_view(1)
                    .ok()?;
                self.block_by_hash(hash_value_to_h256(hash))
            }
            BlockNumber::LatestVoted => self.latest_voted(),
        }
    }

    fn consensus_blocks(&self) -> Option<Vec<Block>> {
        let blocks = self.pos_handler.consensus_db().get_blocks().ok()?;
        let block_ids = blocks.values().map(|b| b.id()).collect::<Vec<_>>();
        debug!("consensus_blocks: block_ids={:?}", block_ids);
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
        let latest_epoch_state = self
            .pos_handler
            .pos_ledger_db()
            .get_latest_pos_state()
            .epoch_state()
            .clone();
        // map to Committed block
        let rpc_blocks = blocks
            .into_iter()
            .filter(|b| b.epoch() == latest_epoch_state.epoch)
            .map(|b| {
                let mut rpc_block = Block {
                    hash: hash_value_to_h256(b.id()),
                    epoch: U64::from(b.epoch()),
                    round: U64::from(b.round()),
                    last_tx_number: Default::default(),
                    miner: b.author().map(|a| H256::from(a.to_u8())),
                    parent_hash: hash_value_to_h256(b.parent_id()),
                    timestamp: U64::from(b.timestamp_usecs()),
                    pivot_decision: Default::default(),
                    height: Default::default(),
                    signatures: vec![],
                };
                // Executed blocks are committed and pruned before ConsensusDB.
                // If we get a block from ConsensusDB and it's pruned before we
                // get the executed block here, its version and
                // pivot decision would be missing.
                // If this consensus block is not on a fork, its CommittedBlock
                // should be accessible in this case.
                if let Ok(executed_block) =
                    self.pos_handler.cached_db().get_block(&b.id())
                {
                    let executed = executed_block.lock();
                    if let Some(version) = executed.output().version() {
                        rpc_block.last_tx_number = U64::from(version);
                    }
                    rpc_block.pivot_decision = executed
                        .output()
                        .pivot_block()
                        .as_ref()
                        .map(|p| Decision::from(p));
                    rpc_block.height = U64::from(
                        executed
                            .output()
                            .executed_trees()
                            .pos_state()
                            .current_view(),
                    );
                } else if let Ok(committed_block) = self
                    .pos_handler
                    .pos_ledger_db()
                    .get_committed_block_by_hash(&b.id())
                {
                    rpc_block.last_tx_number = committed_block.version.into();
                    rpc_block.pivot_decision =
                        Some(Decision::from(&committed_block.pivot_decision));
                    rpc_block.height = U64::from(committed_block.view);
                }
                if let Some(qc) = qcs.get(&b.id()) {
                    let signatures = qc
                        .ledger_info()
                        .signatures()
                        .iter()
                        .map(|(a, _s)| {
                            let voting_power = latest_epoch_state
                                .verifier()
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
            .collect::<Vec<_>>();
        Some(rpc_blocks)
    }

    fn latest_voted(&self) -> Option<Block> {
        self.consensus_blocks()
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b.pivot_decision.is_some())
                    .last()
                    .cloned()
            })
            .flatten()
    }

    fn consensus_block_by_number(&self, number: U64) -> Option<Block> {
        self.consensus_blocks()?
            .into_iter()
            .find(|b| b.height == number)
    }

    fn consensus_block_by_hash(&self, hash: H256) -> Option<Block> {
        self.consensus_blocks()?
            .into_iter()
            .find(|b| b.hash == hash)
    }

    fn tx_by_version(&self, version: u64) -> Option<Transaction> {
        let pos_ledger_db = self.pos_handler.pos_ledger_db();
        match pos_ledger_db.get_transaction(version).ok()? {
            CoreTransaction::UserTransaction(signed_tx) => {
                let mut block_hash: Option<H256> = None;
                let mut block_number: Option<U64> = None;
                let mut timestamp: Option<U64> = None;
                let block_meta = pos_ledger_db
                    .get_transaction_block_meta(version)
                    .unwrap_or(None);
                if let Some((_, bm)) = block_meta {
                    block_hash = Some(hash_value_to_h256(bm.id()));
                    timestamp = Some(U64::from(bm.timestamp_usec()));
                    if let Some(block) = self.block_by_hash(block_hash?) {
                        block_number = Some(block.height);
                    }
                }
                let status = pos_ledger_db
                    .get_transaction_info(version)
                    .ok()
                    .map(|tx| RpcTransactionStatus::from(tx.status().clone()));
                Some(Transaction {
                    hash: hash_value_to_h256(signed_tx.hash()),
                    from: H256::from(signed_tx.sender().to_u8()),
                    block_hash,
                    block_number,
                    timestamp,
                    number: U64::from(version),
                    payload: Some(signed_tx.payload().clone().into()),
                    status,
                    tx_type: tx_type(signed_tx.payload().clone()),
                })
            }
            CoreTransaction::GenesisTransaction(_) => None,
            CoreTransaction::BlockMetadata(block_meta) => {
                let block_number = self
                    .block_by_hash(hash_value_to_h256(block_meta.id()))
                    .map(|b| U64::from(b.height));
                let mut tx = Transaction {
                    hash: Default::default(),
                    from: Default::default(), // TODO
                    block_hash: Some(hash_value_to_h256(block_meta.id())),
                    block_number,
                    timestamp: Some(U64::from(block_meta.timestamp_usec())),
                    number: U64::from(version),
                    payload: None,
                    status: None,
                    tx_type: RpcTransactionType::BlockMetadata,
                };
                if let Some(tx_info) =
                    pos_ledger_db.get_transaction_info(version).ok()
                {
                    let status =
                        RpcTransactionStatus::from(tx_info.status().clone());
                    tx.status = Some(status);
                    tx.hash = hash_value_to_h256(tx_info.transaction_hash());
                }
                Some(tx)
            }
        }
    }

    fn ledger_info_by_block_number(
        &self, block_number: BlockNumber,
    ) -> Option<LedgerInfoWithSignatures> {
        // TODO: Get hash without getting the block.
        let block_hash = self.block_by_number(block_number.clone())?.hash;
        debug!(
            "ledger_info_by_block_number {:?} {:?}",
            block_number, block_hash
        );
        self.pos_handler
            .pos_ledger_db()
            .get_block_ledger_info(
                &HashValue::from_slice(block_hash.as_bytes()).unwrap(),
            )
            .ok()
    }

    fn ledger_info_by_epoch_and_round(
        &self, epoch: u64, round: u64,
    ) -> Option<LedgerInfoWithSignatures> {
        let block_hash = self
            .pos_handler
            .pos_ledger_db()
            .get_block_hash_by_epoch_and_round(epoch, round)
            .ok()?;
        self.pos_handler
            .pos_ledger_db()
            .get_block_ledger_info(&block_hash)
            .ok()
    }
}

fn map_votes(list: &StatusList) -> Vec<VotePowerState> {
    let mut ans = Vec::with_capacity(list.len());
    for item in list.iter() {
        ans.push(VotePowerState {
            end_block_number: U64::from(item.view),
            power: U64::from(item.votes),
        })
    }
    ans
}

pub fn hash_value_to_h256(h: HashValue) -> H256 {
    hexstr_to_h256(h.to_hex().as_str())
}

impl Pos for PosHandler {
    fn pos_status(&self) -> JsonRpcResult<Status> { Ok(self.status_impl()) }

    fn pos_account(
        &self, address: H256, view: Option<U64>,
    ) -> JsonRpcResult<Account> {
        into_jsonrpc_result(self.account_impl(address, view))
    }

    fn pos_account_by_pow_address(
        &self, address: RpcAddress, view: Option<U64>,
    ) -> JsonRpcResult<Account> {
        into_jsonrpc_result(self.account_by_pow_address_impl(address, view))
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

    fn pos_transaction_by_number(
        &self, number: U64,
    ) -> JsonRpcResult<Option<Transaction>> {
        Ok(self.tx_by_version(number.as_u64()))
    }

    fn pos_consensus_blocks(&self) -> JsonRpcResult<Vec<Block>> {
        Ok(self.consensus_blocks().unwrap_or(vec![]))
    }

    fn pos_get_epoch_state(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<RpcEpochState>> {
        Ok(self
            .epoch_state_by_epoch_number(epoch.as_u64())
            .map(|e| (&e).into()))
    }

    fn pos_get_ledger_info_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<RpcLedgerInfoWithSignatures>> {
        Ok(self
            .ledger_info_by_epoch(epoch.as_u64())
            .map(|l| (&l).into()))
    }

    fn pos_get_ledger_info_by_block_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<RpcLedgerInfoWithSignatures>> {
        Ok(self
            .ledger_info_by_block_number(number)
            .map(|l| (&l).into()))
    }

    fn pos_get_ledger_info_by_epoch_and_round(
        &self, epoch: U64, round: U64,
    ) -> JsonRpcResult<Option<RpcLedgerInfoWithSignatures>> {
        Ok(self
            .ledger_info_by_epoch_and_round(epoch.as_u64(), round.as_u64())
            .map(|l| (&l).into()))
    }

    fn pos_get_ledger_infos_by_epoch(
        &self, start_epoch: U64, end_epoch: U64,
    ) -> JsonRpcResult<Vec<RpcLedgerInfoWithSignatures>> {
        Ok(self
            .ledger_infos_by_epoch(start_epoch.as_u64(), end_epoch.as_u64())
            .iter()
            .map(|l| l.into())
            .collect())
    }

    fn pos_get_rewards_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<PoSEpochReward>> {
        let reward = self
            .pow_data_manager
            .pos_reward_by_pos_epoch(epoch.as_u64())
            .map(|reward_info| {
                convert_to_pos_epoch_reward(reward_info, self.network_type).ok()
            })
            .unwrap_or(None);
        Ok(reward)
    }
}

pub fn convert_to_pos_epoch_reward(
    reward: PosRewardInfo, network_type: Network,
) -> Result<PoSEpochReward, String> {
    let default_value = U256::from(0);
    let mut account_reward_map = HashMap::new();
    let mut account_address_map = HashMap::new();
    for r in reward.account_rewards.iter() {
        let key = r.pos_identifier;
        let r1 = account_reward_map.get(&key).unwrap_or(&default_value);
        let merged_reward = r.reward + r1;
        account_reward_map.insert(key, merged_reward);

        let rpc_address = RpcAddress::try_from_h160(r.address, network_type)?;
        account_address_map.insert(key, rpc_address);
    }
    let account_rewards = account_reward_map
        .iter()
        .map(|(k, v)| Reward {
            pos_address: *k,
            pow_address: account_address_map.get(k).unwrap().clone(),
            reward: *v,
        })
        .filter(|r| r.reward > U256::from(0))
        .collect();
    Ok(PoSEpochReward {
        pow_epoch_hash: reward.execution_epoch_hash,
        account_rewards,
    })
}
