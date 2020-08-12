// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod debug_recompute;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockHashAuthorValue<ValueType>(
    pub H256,
    pub Address,
    pub ValueType,
);

//#[derive(Debug, Serialize, Deserialize)]
//pub struct BlockHashValue<ValueType>(pub H256, pub ValueType);

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorValue<ValueType>(pub Address, pub ValueType);

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeEpochDebugRecord {
    // Basic information.
    pub block_height: u64,
    pub block_hash: H256,
    pub parent_epoch_hash: H256,
    pub parent_state_root: StateRootWithAuxInfo,
    pub reward_epoch_hash: Option<H256>,
    pub anticone_penalty_cutoff_epoch_hash: Option<H256>,

    // Blocks.
    pub block_hashes: Vec<H256>,
    pub block_txs: Vec<usize>,
    pub transactions: Vec<Arc<SignedTransaction>>,

    // Rewards. Rewards for anticone overlimit blocks may be skipped.
    pub block_authors: Vec<Address>,
    pub no_reward_blocks: Vec<H256>,
    pub block_rewards: Vec<BlockHashAuthorValue<U256>>,
    pub anticone_penalties: Vec<BlockHashAuthorValue<U256>>,
    // pub anticone_set_size: Vec<BlockHashValue<usize>>,
    pub tx_fees: Vec<BlockHashAuthorValue<U256>>,
    pub secondary_rewards: Vec<BlockHashAuthorValue<U256>>,
    pub block_final_rewards: Vec<BlockHashAuthorValue<U256>>,
    pub merged_rewards_by_author: Vec<AuthorValue<U256>>,

    // State root sequence.
    // TODO: the fields below are not yet filled for debugging.
    pub delta_roots_post_tx: Vec<H256>,
    pub state_root_after_applying_rewards: StateRootWithAuxInfo,

    // Storage operations.
    // op name, key, maybe_value
    pub state_ops: Vec<StateOp>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StateOp {
    IncentiveLevelOp {
        op_name: String,
        key: Vec<u8>,
        maybe_value: Option<Vec<u8>>,
    },
    StorageLevelOp {
        op_name: String,
        key: Vec<u8>,
        maybe_value: Option<Vec<u8>>,
    },
}

impl Default for ComputeEpochDebugRecord {
    fn default() -> Self {
        Self {
            block_hash: Default::default(),
            block_height: 0,
            parent_epoch_hash: Default::default(),
            parent_state_root: StateRootWithAuxInfo::genesis(
                &Default::default(),
            ),
            reward_epoch_hash: None,
            anticone_penalty_cutoff_epoch_hash: None,
            block_hashes: Default::default(),
            block_txs: Default::default(),
            transactions: Default::default(),
            block_authors: Default::default(),
            no_reward_blocks: Default::default(),
            block_rewards: Default::default(),
            anticone_penalties: Default::default(),
            tx_fees: Default::default(),
            secondary_rewards: Default::default(),
            block_final_rewards: Default::default(),
            merged_rewards_by_author: Default::default(),
            delta_roots_post_tx: Default::default(),
            state_root_after_applying_rewards: StateRootWithAuxInfo::genesis(
                &Default::default(),
            ),
            state_ops: Default::default(),
        }
    }
}

use cfx_internal_common::StateRootWithAuxInfo;
use cfx_types::{Address, H256, U256};
use primitives::SignedTransaction;
use serde_derive::{Deserialize, Serialize};
use std::{sync::Arc, vec::Vec};
