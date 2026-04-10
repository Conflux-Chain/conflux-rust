// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    errors::build_rpc_server_error,
    traits::pos::Pos,
    types::{
        pos::{
            Account, Block, BlockNumber, CommitteeState, EpochState,
            LedgerInfoWithSignatures, PoSEpochReward, Status, Transaction,
        },
        RpcAddress,
    },
    RpcInterceptor,
};
use cfx_addr::Network;
use cfx_rpc_cfx_api::PosRpcServer;
pub use cfx_rpc_cfx_impl::{
    convert_to_pos_epoch_reward, hash_value_to_h256,
    PosHandler as NewPosHandler,
};
use cfx_rpc_utils::error::jsonrpc_error_helpers::error_object_owned_to_jsonrpc_error as convert_error;
use cfx_types::{H256, U64};
use cfxcore::{
    consensus::pos_handler::PosVerifier, BlockDataManager, SharedConsensusGraph,
};
use jsonrpc_core::Result as JsonRpcResult;
use std::sync::Arc;

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
            None => Err(build_rpc_server_error(
                crate::rpc::errors::codes::POS_NOT_ENABLED,
                "PoS chain is not enabled".into(),
            )),
        }
    }
}

pub struct PosHandler {
    inner: NewPosHandler,
}

impl PosHandler {
    pub fn new(
        pos_handler: Arc<PosVerifier>, pow_data_manager: Arc<BlockDataManager>,
        network_type: Network, consensus: SharedConsensusGraph,
    ) -> Self {
        PosHandler {
            inner: NewPosHandler::new(
                pos_handler,
                pow_data_manager,
                network_type,
                consensus,
            ),
        }
    }
}

impl Pos for PosHandler {
    fn pos_status(&self) -> JsonRpcResult<Status> {
        self.inner.pos_status().map_err(convert_error)
    }

    fn pos_account(
        &self, address: H256, view: Option<U64>,
    ) -> JsonRpcResult<Account> {
        self.inner.pos_account(address, view).map_err(convert_error)
    }

    fn pos_account_by_pow_address(
        &self, address: RpcAddress, view: Option<U64>,
    ) -> JsonRpcResult<Account> {
        self.inner
            .pos_account_by_pow_address(address, view)
            .map_err(convert_error)
    }

    fn pos_committee(
        &self, view: Option<U64>,
    ) -> JsonRpcResult<CommitteeState> {
        self.inner.pos_committee(view).map_err(convert_error)
    }

    fn pos_block_by_hash(&self, hash: H256) -> JsonRpcResult<Option<Block>> {
        self.inner.pos_block_by_hash(hash).map_err(convert_error)
    }

    fn pos_block_by_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<Block>> {
        self.inner
            .pos_block_by_number(number)
            .map_err(convert_error)
    }

    fn pos_transaction_by_number(
        &self, number: U64,
    ) -> JsonRpcResult<Option<Transaction>> {
        self.inner
            .pos_transaction_by_number(number)
            .map_err(convert_error)
    }

    fn pos_consensus_blocks(&self) -> JsonRpcResult<Vec<Block>> {
        self.inner.pos_consensus_blocks().map_err(convert_error)
    }

    fn pos_get_epoch_state(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<EpochState>> {
        self.inner.pos_get_epoch_state(epoch).map_err(convert_error)
    }

    fn pos_get_ledger_info_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>> {
        self.inner
            .pos_get_ledger_info_by_epoch(epoch)
            .map_err(convert_error)
    }

    fn pos_get_ledger_info_by_block_number(
        &self, number: BlockNumber,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>> {
        self.inner
            .pos_get_ledger_info_by_block_number(number)
            .map_err(convert_error)
    }

    fn pos_get_ledger_info_by_epoch_and_round(
        &self, epoch: U64, round: U64,
    ) -> JsonRpcResult<Option<LedgerInfoWithSignatures>> {
        self.inner
            .pos_get_ledger_info_by_epoch_and_round(epoch, round)
            .map_err(convert_error)
    }

    fn pos_get_ledger_infos_by_epoch(
        &self, start_epoch: U64, end_epoch: U64,
    ) -> JsonRpcResult<Vec<LedgerInfoWithSignatures>> {
        self.inner
            .pos_get_ledger_infos_by_epoch(start_epoch, end_epoch)
            .map_err(convert_error)
    }

    fn pos_get_rewards_by_epoch(
        &self, epoch: U64,
    ) -> JsonRpcResult<Option<PoSEpochReward>> {
        self.inner
            .pos_get_rewards_by_epoch(epoch)
            .map_err(convert_error)
    }
}
