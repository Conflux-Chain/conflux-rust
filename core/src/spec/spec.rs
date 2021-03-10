// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::message::Bytes;
use cfx_internal_common::ChainIdParams;
use cfx_parameters::{
    consensus::{
        BN128_ENABLE_NUMBER, ONE_UCFX_IN_DRIP,
        TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT,
    },
    consensus_internal::{
        ANTICONE_PENALTY_RATIO, INITIAL_BASE_MINING_REWARD_IN_UCFX,
        MINING_REWARD_TANZANITE_IN_UCFX,
    },
};
use cfx_types::{Address, H256, U256, U512};
use primitives::block::BlockHeight;
use std::collections::BTreeMap;

struct Spec {
    /// User friendly spec name
    pub name: String,
    /// Common parameters for different chain.
    pub params: CommonParams,

    /// The genesis block's parent hash field.
    pub parent_hash: H256,
    /// The genesis block's author field.
    pub author: Address,
    /// The genesis block's difficulty field.
    pub difficulty: U256,
    /// The genesis block's gas limit field.
    pub gas_limit: U256,
    /// The genesis block's gas used field.
    pub gas_used: U256,
    /// The genesis block's timestamp field.
    pub timestamp: u64,
    /// Transactions root of the genesis block. Should be KECCAK_NULL_RLP.
    pub transactions_root: H256,
    /// Receipts root of the genesis block. Should be KECCAK_NULL_RLP.
    pub receipts_root: H256,
    /// The genesis block's extra data field.
    pub custom: Bytes,
}

impl Default for Spec {
    fn default() -> Self { unimplemented!() }
}

#[derive(Debug)]
pub struct CommonParams {
    /// Account start nonce.
    pub account_start_nonce: U256,
    /// Maximum size of extra data.
    pub maximum_extra_data_size: usize,
    /// Network id.
    pub network_id: u64,
    /// Chain id.
    pub chain_id: ChainIdParams,
    /// Main subprotocol name.
    pub subprotocol_name: String,
    /// Minimum gas limit.
    pub min_gas_limit: U256,
    /// Gas limit bound divisor (how much gas limit can change per block)
    pub gas_limit_bound_divisor: U256,
    /// Number of first block where max code size limit is active.
    /// Maximum size of transaction's RLP payload.
    pub max_transaction_size: usize,
    /// Anticone penalty ratio for reward processing.
    /// It should be less than `timer_chain_beta`.
    pub anticone_penalty_ratio: u64,
    /// Initial base rewards according to block height.
    pub base_block_rewards: BTreeMap<BlockHeight, U256>,

    /// Number of first block where bn128 built-in contract enabled.
    pub alt_bn128_transition: u64,
    /// The height to change block base reward.
    /// The block `custom` field of this height is required to be
    /// `tanzanite_transition_header_custom`.
    pub tanzanite_transition: BlockHeight,
}

impl Default for CommonParams {
    fn default() -> Self {
        let mut base_block_rewards = BTreeMap::new();
        base_block_rewards.insert(0, INITIAL_BASE_MINING_REWARD_IN_UCFX.into());
        CommonParams {
            account_start_nonce: 0x00.into(),
            maximum_extra_data_size: 0x20,
            network_id: 0x1,
            chain_id: Default::default(),
            subprotocol_name: "cfx".into(),
            min_gas_limit: 10_000_000.into(),
            gas_limit_bound_divisor: 0x0400.into(),
            max_transaction_size: 300 * 1024,
            anticone_penalty_ratio: ANTICONE_PENALTY_RATIO,
            base_block_rewards,
            alt_bn128_transition: BN128_ENABLE_NUMBER,
            tanzanite_transition: 0,
        }
    }
}

impl CommonParams {
    pub fn common_params(
        chain_id: ChainIdParams, anticone_penalty_ratio: u64,
        tanzanite_transition: BlockHeight,
    ) -> Self
    {
        let mut base_block_rewards = BTreeMap::new();
        base_block_rewards.insert(0, INITIAL_BASE_MINING_REWARD_IN_UCFX.into());
        base_block_rewards.insert(
            tanzanite_transition,
            MINING_REWARD_TANZANITE_IN_UCFX.into(),
        );
        let mut params = CommonParams::default();
        params.chain_id = chain_id;
        params.anticone_penalty_ratio = anticone_penalty_ratio;
        params.tanzanite_transition = tanzanite_transition;
        params.base_block_rewards = base_block_rewards;
        params
    }

    /// Return the base reward for a block.
    /// `past_block_count` may be used for reward decay again in the future.
    pub fn base_reward_in_ucfx(
        &self, _past_block_count: u64, height: BlockHeight,
    ) -> U512 {
        let (_, start_base_ward) = self.base_block_rewards.iter()
            .rev()
            .find(|&(block, _)| *block <= height)
            .expect("Current block's reward is not found; this indicates a chain config error");
        // Possible decay computation based on past_block_count.
        U512::from(start_base_ward) * U512::from(ONE_UCFX_IN_DRIP)
    }

    pub fn custom_prefix(&self, height: BlockHeight) -> Option<Vec<Bytes>> {
        if height >= self.tanzanite_transition {
            Some(vec![TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else {
            None
        }
    }
}
