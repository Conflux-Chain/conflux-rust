// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{
    pos::{
        Account, Block, BlockNumber, CommitteeState, EpochState,
        LedgerInfoWithSignatures, PoSEpochReward, Status, Transaction,
    },
    RpcAddress,
};
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
        &self, address: H256, view: Option<U64>,
    ) -> JsonRpcResult<Account>;

    #[rpc(name = "pos_getAccountByPowAddress")]
    fn pos_account_by_pow_address(
        &self, address: RpcAddress, view: Option<U64>,
    ) -> JsonRpcResult<Account>;

    #[rpc(name = "pos_getCommittee")]
    fn pos_committee(&self, view: Option<U64>)
        -> JsonRpcResult<CommitteeState>;

    #[rpc(name = "pos_getBlockByHash")]
    fn pos_block_by_hash(&self, hash: H256) -> JsonRpcResult<Option<Block>>;

    #[rpc(name = "pos_getBlockByNumber")]
    fn pos_block_by_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<Block>>;

    #[rpc(name = "pos_getTransactionByNumber")]
    fn pos_transaction_by_number(
        &self, number: U64,
    ) -> JsonRpcResult<Option<Transaction>>;

    // debug rpc
    #[rpc(name = "pos_getConsensusBlocks")]
    fn pos_consensus_blocks(&self) -> JsonRpcResult<Vec<Block>>;

    // debug rpc
    #[rpc(name = "pos_getEpochState")]
    fn pos_get_epoch_state(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<EpochState>>;

    // debug rpc
    #[rpc(name = "pos_getLedgerInfoByEpoch")]
    fn pos_get_ledger_info_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>>;

    #[rpc(name = "pos_getLedgerInfoByBlockNumber")]
    fn pos_get_ledger_info_by_block_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>>;

    #[rpc(name = "pos_getLedgerInfoByEpochAndRound")]
    fn pos_get_ledger_info_by_epoch_and_round(
        &self, epoch: U64, round: U64,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>>;

    // debug rpc
    #[rpc(name = "pos_getLedgerInfosByEpoch")]
    fn pos_get_ledger_infos_by_epoch(
        &self, start_epoch: U64, end_epoch: U64,
    ) -> JsonRpcResult<Vec<LedgerInfoWithSignatures>>;

    #[rpc(name = "pos_getRewardsByEpoch")]
    fn pos_get_rewards_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<PoSEpochReward>>;
}
