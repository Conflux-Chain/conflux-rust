use super::ConsensusGraph;

use crate::consensus::consensus_inner::{ConsensusGraphInner, StateBlameInfo};

use cfx_parameters::consensus::*;
use cfx_types::{H256, U256};
use primitives::pos::PosBlockId;

use std::{thread::sleep, time::Duration};

impl ConsensusGraph {
    /// Determine whether the next mined block should have adaptive weight or
    /// not
    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        referees: &Vec<H256>, difficulty: &U256,
        pos_reference: Option<PosBlockId>,
    ) -> bool {
        let parent_index =
            *inner.hash_to_arena_indices.get(parent_hash).expect(
                "parent_hash is the pivot chain tip,\
                 so should still exist in ConsensusInner",
            );
        let referee_indices: Vec<_> = referees
            .iter()
            .map(|h| {
                *inner
                    .hash_to_arena_indices
                    .get(h)
                    .expect("Checked by the caller")
            })
            .collect();
        inner.check_mining_adaptive_block(
            parent_index,
            referee_indices,
            *difficulty,
            pos_reference,
        )
    }

    /// Wait for the generation and the execution completion of a block in the
    /// consensus graph. This API is used mainly for testing purpose
    pub fn wait_for_generation(&self, hash: &H256) {
        while !self
            .inner
            .read_recursive()
            .hash_to_arena_indices
            .contains_key(hash)
        {
            sleep(Duration::from_millis(1));
        }
        let best_state_block =
            self.inner.read_recursive().best_state_block_hash();
        match self.executor.wait_for_result(best_state_block) {
            Ok(_) => (),
            Err(msg) => warn!("wait_for_generation() gets the following error from the ConsensusExecutor: {}", msg)
        }
        // Ensure that `best_info` has been updated when this returns, so if we
        // are calling RPCs to generate many blocks, they will form a
        // strict chain. Note that it's okay to call `update_best_info`
        // multiple times, and we only generate blocks after
        // `ready_for_mining` is true.
        self.update_best_info(true);
        if let Err(e) = self
            .txpool
            .notify_new_best_info(self.best_info.read_recursive().clone())
        {
            error!("wait for generation: notify_new_best_info err={:?}", e);
        }
    }

    /// After considering the latest `pos_reference`, `parent_hash` may become
    /// an invalid choice, so this function tries to update the parent and
    /// referee choices with `pos_reference` provided.
    pub fn choose_correct_parent(
        &self, parent_hash: &mut H256, referees: &mut Vec<H256>,
        blame_info: &mut StateBlameInfo, pos_reference: Option<PosBlockId>,
    ) {
        let correct_parent_hash = {
            if let Some(pos_ref) = &pos_reference {
                loop {
                    let inner = self.inner.read();
                    let pivot_decision = inner
                        .pos_verifier
                        .get_pivot_decision(pos_ref)
                        .expect("pos ref committed");
                    if inner.hash_to_arena_indices.contains_key(&pivot_decision)
                        || inner.pivot_block_processed(&pivot_decision)
                    {
                        // If this pos ref is processed in catching-up, its
                        // pivot decision may have not been processed
                        break;
                    } else {
                        // Wait without holding consensus inner lock.
                        drop(inner);
                        warn!("Wait for PoW to catch up with PoS");
                        sleep(Duration::from_secs(1));
                    }
                }
            }
            // recompute `blame_info` needs locking `self.inner`, so we limit
            // the lock scope here.
            let mut inner = self.inner.write();
            referees.retain(|h| inner.hash_to_arena_indices.contains_key(h));
            let parent_index =
                *inner.hash_to_arena_indices.get(parent_hash).expect(
                    "parent_hash is the pivot chain tip,\
                     so should still exist in ConsensusInner",
                );
            let referee_indices: Vec<_> = referees
                .iter()
                .map(|h| {
                    *inner
                        .hash_to_arena_indices
                        .get(h)
                        .expect("Checked by the caller")
                })
                .collect();
            let correct_parent = inner.choose_correct_parent(
                parent_index,
                referee_indices,
                pos_reference,
            );
            inner.arena[correct_parent].hash
        };

        if correct_parent_hash != *parent_hash {
            debug!(
                "Change parent from {:?} to {:?}",
                parent_hash, correct_parent_hash
            );

            // correct_parent may be among referees, so check and remove it.
            referees.retain(|i| *i != correct_parent_hash);

            // Old parent is a valid block terminal to refer to.
            if referees.len() < self.config.referee_bound {
                referees.push(*parent_hash);
            }

            // correct_parent may not be on the pivot chain, so recompute
            // blame_info if needed.
            *blame_info = self
                .force_compute_blame_and_deferred_state_for_generation(
                    &correct_parent_hash,
                )
                .expect("blame info computation error");
            *parent_hash = correct_parent_hash;
        }
    }

    /// Force the engine to recompute the deferred state root for a particular
    /// block given a delay.
    pub fn force_compute_blame_and_deferred_state_for_generation(
        &self, parent_block_hash: &H256,
    ) -> Result<StateBlameInfo, String> {
        {
            let inner = &mut *self.inner.write();
            let hash = inner
                .get_state_block_with_delay(
                    parent_block_hash,
                    DEFERRED_STATE_EPOCH_COUNT as usize - 1,
                )?
                .clone();
            self.executor.compute_state_for_block(&hash, inner)?;
        }
        self.executor.get_blame_and_deferred_state_for_generation(
            parent_block_hash,
            &self.inner,
        )
    }

    pub fn get_blame_and_deferred_state_for_generation(
        &self, parent_block_hash: &H256,
    ) -> Result<StateBlameInfo, String> {
        self.executor.get_blame_and_deferred_state_for_generation(
            parent_block_hash,
            &self.inner,
        )
    }
}
