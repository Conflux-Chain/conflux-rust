pub use crate::consensus::consensus_inner::ConsensusGraphInner;

use cfx_parameters::consensus_internal::REWARD_EPOCH_COUNT;
use cfx_types::{H256, U256};
use metrics::{register_meter_with_group, Meter, MeterTimer};
use primitives::EpochId;

use std::{
    collections::HashSet,
    sync::{atomic::Ordering, Arc},
};

use super::ConsensusGraph;

lazy_static! {
    static ref CONSENSIS_ON_NEW_BLOCK_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "consensus_on_new_block_timer");
}

impl ConsensusGraph {
    /// Reset the information in consensus graph with only checkpoint
    /// information kept.
    pub fn reset(&self) {
        let old_consensus_inner = &mut *self.inner.write();

        let cur_era_genesis_hash =
            self.data_man.get_cur_consensus_era_genesis_hash();
        let cur_era_stable_hash =
            self.data_man.get_cur_consensus_era_stable_hash();
        let new_consensus_inner = ConsensusGraphInner::with_era_genesis(
            old_consensus_inner.pow_config.clone(),
            old_consensus_inner.pow.clone(),
            old_consensus_inner.pos_verifier.clone(),
            self.data_man.clone(),
            old_consensus_inner.inner_conf.clone(),
            &cur_era_genesis_hash,
            cur_era_stable_hash,
        );
        *old_consensus_inner = new_consensus_inner;
        debug!("Build new consensus graph for sync-recovery with identified genesis {} stable block {}", cur_era_genesis_hash, cur_era_stable_hash);

        self.confirmation_meter.clear();
    }

    /// Return the blocks without bodies in the subtree of stable genesis and
    /// the blocks in the `REWARD_EPOCH_COUNT` epochs before it. Block
    /// bodies of other blocks in the consensus graph will never be needed
    /// for executions after this stable genesis, as long as the checkpoint
    /// is not reverted.
    pub fn get_blocks_needing_bodies(&self) -> HashSet<H256> {
        let inner = self.inner.read();
        // TODO: This may not be stable genesis with other configurations.
        let stable_genesis = self.data_man.get_cur_consensus_era_stable_hash();
        let mut missing_body_blocks = HashSet::new();
        for block_hash in inner
            .get_subtree(&stable_genesis)
            .expect("stable is in consensus")
        {
            if self.data_man.block_by_hash(&block_hash, false).is_none() {
                missing_body_blocks.insert(block_hash);
            }
        }
        // We also need the block bodies before the checkpoint to compute
        // rewards.
        let stable_height = self
            .data_man
            .block_height_by_hash(&stable_genesis)
            .expect("stable exist");
        let reward_start_epoch = if stable_height >= REWARD_EPOCH_COUNT {
            stable_height - REWARD_EPOCH_COUNT + 1
        } else {
            1
        };
        for height in reward_start_epoch..=stable_height {
            for block_hash in self
                .data_man
                .executed_epoch_set_hashes_from_db(height)
                .expect("epoch sets before stable should exist")
            {
                if self.data_man.block_by_hash(&block_hash, false).is_none() {
                    missing_body_blocks.insert(block_hash);
                }
            }
        }
        missing_body_blocks.remove(&self.data_man.true_genesis.hash());
        missing_body_blocks
    }

    pub fn enter_normal_phase(&self) {
        self.ready_for_mining.store(true, Ordering::SeqCst);
        self.update_best_info(true);
        self.txpool.set_ready_for_mining();
        self.txpool
            .notify_new_best_info(self.best_info.read_recursive().clone())
            .expect("No DB error")
    }

    pub fn set_initial_sequence_number(&self, initial_sn: u64) {
        self.inner.write().set_initial_sequence_number(initial_sn);
    }

    /// Find a trusted blame block for snapshot full sync
    pub fn get_trusted_blame_block_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<H256> {
        self.inner
            .read()
            .get_trusted_blame_block_for_snapshot(snapshot_epoch_id)
    }

    /// Return the epoch that we are going to sync the state
    pub fn get_to_sync_epoch_id(&self) -> EpochId {
        self.inner.read().get_to_sync_epoch_id()
    }

    /// Check if we have downloaded all the headers to find the lowest needed
    /// checkpoint. We can enter `CatchUpCheckpoint` if it's true.
    pub fn catch_up_completed(&self, peer_median_epoch: u64) -> bool {
        let stable_genesis_height = self
            .data_man
            .block_height_by_hash(
                &self.data_man.get_cur_consensus_era_stable_hash(),
            )
            .expect("stable exists");

        if self.best_epoch_number() < stable_genesis_height {
            // For an archive node, if its terminals are overwritten with
            // earlier blocks during recovery, it's possible to
            // reach here with a pivot chain before stable era
            // checkpoint. Here we wait for it to recover the missing headers
            // after the overwritten terminals.
            return false;
        }
        if let Some(target_epoch) = self.config.sync_state_starting_epoch {
            if stable_genesis_height < target_epoch {
                return false;
            }
        }
        if let Some(gap) = self.config.sync_state_epoch_gap {
            if self.best_epoch_number() + gap < peer_median_epoch {
                return false;
            }
        }
        true
    }

    // FIXME store this in BlockDataManager
    /// Return the sequence number of the current era genesis hash.
    pub fn current_era_genesis_seq_num(&self) -> u64 {
        self.inner.read_recursive().current_era_genesis_seq_num()
    }

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    pub fn on_new_block(&self, hash: &H256) {
        let _timer =
            MeterTimer::time_func(CONSENSIS_ON_NEW_BLOCK_TIMER.as_ref());
        self.statistics.inc_consensus_graph_processed_block_count();

        self.new_block_handler.on_new_block(
            &mut *self.inner.write(),
            &self.confirmation_meter,
            hash,
        );

        let ready_for_mining = self.ready_for_mining.load(Ordering::SeqCst);
        self.update_best_info(ready_for_mining);
        if ready_for_mining {
            self.txpool
                .notify_new_best_info(self.best_info.read().clone())
                // FIXME: propogate error.
                .expect(&concat!(file!(), ":", line!(), ":", column!()));
        }
        debug!("Finish Consensus::on_new_block for {:?}", hash);
    }

    /// This function is a wrapper function for the function in the confirmation
    /// meter. The synchronization layer is supposed to call this function
    /// every 2 * BLOCK_PROPAGATION_DELAY seconds
    pub fn update_total_weight_delta_heartbeat(&self) {
        self.confirmation_meter
            .update_total_weight_delta_heartbeat();
    }

    /// construct_pivot_state() rebuild pivot chain state info from db
    /// avoiding intermediate redundant computation triggered by
    /// on_new_block().
    pub fn construct_pivot_state(&self) {
        let inner = &mut *self.inner.write();
        // Ensure that `state_valid` of the first valid block after
        // cur_era_stable_genesis is set
        inner.recover_state_valid();
        self.new_block_handler
            .construct_pivot_state(inner, &self.confirmation_meter);
        inner.finish_block_recovery();
    }

    /// Compute the expected difficulty of a new block given its parent
    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let inner = self.inner.read();
        inner.expected_difficulty(parent_hash)
    }
}
