// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager, consensus::BestInformation,
    state::State, statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
};

use crate::consensus::ConsensusConfig;
use cfx_types::{H256, U256};
use primitives::{
    receipt::Receipt, EpochId, EpochNumber, SignedTransaction, TransactionIndex,
};
use std::{any::Any, sync::Arc};

/// FIXME: redesign this trait
pub trait ConsensusGraphTrait: Send + Sync {
    type ConsensusConfig;

    fn as_any(&self) -> &dyn Any;

    fn get_config(&self) -> &Self::ConsensusConfig;

    fn on_new_block(
        &self, hash: &H256, ignore_body: bool, update_best_info: bool,
    );

    fn update_total_weight_delta_heartbeat(&self) {}

    fn expected_difficulty(&self, parent_hash: &H256) -> U256;

    fn retrieve_old_era_blocks(&self) -> Option<H256>;

    fn construct_pivot_state(&self);

    fn best_info(&self) -> Arc<BestInformation>;

    fn best_epoch_number(&self) -> u64;

    fn latest_checkpoint_epoch_number(&self) -> u64;

    fn latest_confirmed_epoch_number(&self) -> u64;

    fn best_chain_id(&self) -> u32;

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

    // FIXME: return type.
    fn get_transaction_info_by_hash(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, TransactionIndex, Option<(Receipt, U256)>)>;

    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64>;

    fn get_best_state(&self) -> State;

    fn get_trusted_blame_block_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<H256>;

    fn get_to_sync_epoch_id(&self) -> EpochId;

    fn get_trusted_blame_block(&self, stable_hash: &H256) -> Option<H256>;

    fn first_trusted_header_starting_from(
        &self, height: u64, blame_bound: Option<u32>,
    ) -> Option<u64>;

    fn set_initial_sequence_number(&self, initial_sn: u64);

    fn update_best_info(&self);
}

pub type SharedConsensusGraph =
    Arc<dyn ConsensusGraphTrait<ConsensusConfig = ConsensusConfig>>;
