// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Derivative, Clone)]
#[derivative(Debug)]
#[derive(MallocSizeOf)]
pub struct StateAvailabilityBoundary {
    /// This is the hash of blocks in pivot chain based on current graph.
    #[derivative(Debug = "ignore")]
    pub pivot_chain: Vec<H256>,

    pub synced_state_height: u64,
    /// This is the lower boundary height of available state where we can
    /// execute new epochs based on it. Note that `synced_state_height` is
    /// within this bound for execution, but its state cannot be accessed
    /// through `get_state_no_commit`.
    pub lower_bound: u64,
    /// This is the upper boundary height of available state.
    pub upper_bound: u64,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    pub optimistic_executed_height: Option<u64>,
}

impl StateAvailabilityBoundary {
    pub fn new(epoch_hash: H256, epoch_height: u64) -> Self {
        Self {
            pivot_chain: vec![epoch_hash],
            synced_state_height: 0,
            lower_bound: epoch_height,
            upper_bound: epoch_height,
            optimistic_executed_height: None,
        }
    }

    /// Check if the state can be accessed for reading.
    pub fn check_availability(&self, height: u64, block_hash: &H256) -> bool {
        (height == 0 || height != self.synced_state_height)
            && self.lower_bound <= height
            && height <= self.upper_bound
            && {
                let r = self.pivot_chain[(height - self.lower_bound) as usize]
                    == *block_hash;
                if !r {
                    debug!(
                        "pivot_chain={:?} should be {:?} asked is {:?}",
                        self.pivot_chain,
                        self.pivot_chain[(height - self.lower_bound) as usize],
                        block_hash
                    );
                }
                r
            }
    }

    /// Try to update `upper_bound` according to a new executed block.
    pub fn adjust_upper_bound(&mut self, executed_block: &BlockHeader) {
        let next_index = (self.upper_bound - self.lower_bound + 1) as usize;
        if next_index < self.pivot_chain.len()
            && executed_block.height() == self.upper_bound + 1
            && executed_block.hash() == self.pivot_chain[next_index]
        {
            self.upper_bound += 1;
        }
    }

    /// This function will record the most recent synced_state_height for
    /// special case handling.
    pub fn set_synced_state_height(&mut self, synced_state_height: u64) {
        self.synced_state_height = synced_state_height;
    }

    /// This function will set a new lower boundary height of available state.
    /// Caller should make sure the new lower boundary height should be greater
    /// than or equal to current lower boundary height.
    /// Caller should also make sure the new lower boundary height should be
    /// less than or equal to current upper boundary height.
    pub fn adjust_lower_bound(&mut self, new_lower_bound: u64) {
        // If we are going to call this function, `upper_bound` will not be 0
        // unless it is a full node and is in header phase. And we should do
        // nothing in this case.
        if self.upper_bound == 0 {
            return;
        }
        assert!(self.lower_bound <= new_lower_bound);
        assert!(
            new_lower_bound <= self.upper_bound,
            "however {} > {}, self {:?}",
            new_lower_bound,
            self.upper_bound,
            self,
        );
        if self.synced_state_height != 0
            && new_lower_bound > self.synced_state_height + REWARD_EPOCH_COUNT
        {
            self.synced_state_height = 0;
        }
        self.pivot_chain = self
            .pivot_chain
            .split_off((new_lower_bound - self.lower_bound) as usize);
        self.lower_bound = new_lower_bound;
    }
}

use cfx_parameters::consensus_internal::REWARD_EPOCH_COUNT;
use cfx_types::H256;
use derivative::Derivative;
use malloc_size_of_derive::MallocSizeOf;
use primitives::BlockHeader;
