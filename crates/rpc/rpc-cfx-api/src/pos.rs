// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_cfx_types::{
    pos::{
        Account, Block, BlockNumber, CommitteeState, EpochState,
        LedgerInfoWithSignatures, PoSEpochReward, Status, Transaction,
    },
    RpcAddress,
};
use cfx_types::{H256, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// PoS specific rpc interface.
#[rpc(server, namespace = "pos")]
pub trait PosRpc {
    #[method(name = "getStatus")]
    fn pos_status(&self) -> RpcResult<Status>;

    #[method(name = "getAccount")]
    fn pos_account(
        &self, address: H256, view: Option<U64>,
    ) -> RpcResult<Account>;

    #[method(name = "getAccountByPowAddress")]
    fn pos_account_by_pow_address(
        &self, address: RpcAddress, view: Option<U64>,
    ) -> RpcResult<Account>;

    #[method(name = "getCommittee")]
    fn pos_committee(&self, view: Option<U64>) -> RpcResult<CommitteeState>;

    #[method(name = "getBlockByHash")]
    fn pos_block_by_hash(&self, hash: H256) -> RpcResult<Option<Block>>;

    #[method(name = "getBlockByNumber")]
    fn pos_block_by_number(
        &self, number: BlockNumber,
    ) -> RpcResult<Option<Block>>;

    #[method(name = "getTransactionByNumber")]
    fn pos_transaction_by_number(
        &self, number: U64,
    ) -> RpcResult<Option<Transaction>>;

    // debug rpc
    #[method(name = "getConsensusBlocks")]
    fn pos_consensus_blocks(&self) -> RpcResult<Vec<Block>>;

    // debug rpc
    #[method(name = "getEpochState")]
    fn pos_get_epoch_state(&self, epoch: U64) -> RpcResult<Option<EpochState>>;

    // debug rpc
    #[method(name = "getLedgerInfoByEpoch")]
    fn pos_get_ledger_info_by_epoch(
        &self, epoch: U64,
    ) -> RpcResult<Option<LedgerInfoWithSignatures>>;

    #[method(name = "getLedgerInfoByBlockNumber")]
    fn pos_get_ledger_info_by_block_number(
        &self, number: BlockNumber,
    ) -> RpcResult<Option<LedgerInfoWithSignatures>>;

    #[method(name = "getLedgerInfoByEpochAndRound")]
    fn pos_get_ledger_info_by_epoch_and_round(
        &self, epoch: U64, round: U64,
    ) -> RpcResult<Option<LedgerInfoWithSignatures>>;

    // debug rpc
    #[method(name = "getLedgerInfosByEpoch")]
    fn pos_get_ledger_infos_by_epoch(
        &self, start_epoch: U64, end_epoch: U64,
    ) -> RpcResult<Vec<LedgerInfoWithSignatures>>;

    #[method(name = "getRewardsByEpoch")]
    fn pos_get_rewards_by_epoch(
        &self, epoch: U64,
    ) -> RpcResult<Option<PoSEpochReward>>;
}
