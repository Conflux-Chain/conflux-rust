// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager,
    consensus::{BestInformation, ConsensusConfig, TransactionInfo},
    errors::Result as CoreResult,
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    ConsensusGraph,
};
use cfx_statedb::StateDb;
use cfx_storage::StorageState;
use cfx_types::{AllChainID, H256, U256};
use primitives::{EpochId, EpochNumber, SignedTransaction};
use std::{any::Any, collections::HashSet, sync::Arc};

/// FIXME: redesign this trait
pub trait ConsensusGraphTrait: Send + Sync {
    type ConsensusConfig;

    fn as_any(&self) -> &dyn Any;

    fn to_arc_consensus(self: Arc<Self>) -> Arc<ConsensusGraph>;

    fn get_config(&self) -> &Self::ConsensusConfig;

    fn on_new_block(&self, hash: &H256);

    fn update_total_weight_delta_heartbeat(&self) {}

    fn expected_difficulty(&self, parent_hash: &H256) -> U256;

    fn construct_pivot_state(&self);

    fn best_info(&self) -> Arc<BestInformation>;

    fn best_epoch_number(&self) -> u64;

    fn latest_checkpoint_epoch_number(&self) -> u64;

    fn latest_confirmed_epoch_number(&self) -> u64;

    fn latest_finalized_epoch_number(&self) -> u64;

    fn best_chain_id(&self) -> AllChainID;

    fn best_block_hash(&self) -> H256;

    fn current_era_genesis_seq_num(&self) -> u64;

    fn get_data_manager(&self) -> &Arc<BlockDataManager>;

    fn get_tx_pool(&self) -> &SharedTransactionPool;

    fn get_statistics(&self) -> &SharedStatistics;

    fn block_count(&self) -> u64;

    fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, String>;

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String>;

    fn get_skipped_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String>;

    /// Return transaction info for clients.
    /// Note that the skipped transactions (status == 2) will not be returned.
    fn get_transaction_info_by_hash(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, TransactionInfo)>;

    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64>;

    fn get_block_number(
        &self, block_hash: &H256,
    ) -> Result<Option<u64>, String>;

    fn get_trusted_blame_block_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<H256>;

    fn get_to_sync_epoch_id(&self) -> EpochId;

    fn get_trusted_blame_block(&self, stable_hash: &H256) -> Option<H256>;

    fn set_initial_sequence_number(&self, initial_sn: u64);

    fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb>;

    fn get_eth_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb>;

    fn get_storage_state_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StorageState>;

    fn get_blocks_needing_bodies(&self) -> HashSet<H256>;

    fn catch_up_completed(&self, peer_median_epoch: u64) -> bool;

    fn enter_normal_phase(&self);

    fn reset(&self);
}

pub type SharedConsensusGraph =
    Arc<dyn ConsensusGraphTrait<ConsensusConfig = ConsensusConfig>>;
