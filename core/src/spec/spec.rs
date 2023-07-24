// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{message::Bytes, vm};
use cfx_internal_common::{ChainIdParams, ChainIdParamsInner};
use cfx_parameters::{
    block::{EVM_TRANSACTION_BLOCK_RATIO, EVM_TRANSACTION_GAS_RATIO},
    consensus::{
        CIP112_HEADER_CUSTOM_FIRST_ELEMENT,
        DAO_VOTE_HEADER_CUSTOM_FIRST_ELEMENT, ONE_UCFX_IN_DRIP,
        TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT,
    },
    consensus_internal::{
        ANTICONE_PENALTY_RATIO, DAO_PARAMETER_VOTE_PERIOD,
        INITIAL_BASE_MINING_REWARD_IN_UCFX,
    },
};
use cfx_types::{AllChainID, U256, U512};
use primitives::{block::BlockHeight, BlockNumber};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct CommonParams {
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
    /// The ratio of blocks in the EVM transactions
    pub evm_transaction_block_ratio: u64,
    /// The gas ratio of evm transactions for the block can pack the EVM
    /// transactions
    pub evm_transaction_gas_ratio: u64,
    pub params_dao_vote_period: u64,

    /// Set the internal contracts to state at the genesis blocks, even if it
    /// is not activated.
    pub early_set_internal_contracts_states: bool,
    /// The upgrades activated at given block number.
    pub transition_numbers: TransitionsBlockNumber,
    /// The upgrades activated at given block height (a.k.a. epoch number).
    pub transition_heights: TransitionsEpochHeight,
}

#[derive(Default, Debug, Clone)]
pub struct TransitionsBlockNumber {
    /// CIP43: Introduce Finality via Voting Among Staked
    pub cip43a: BlockNumber,
    pub cip43b: BlockNumber,
    /// CIP62: Enable EC-related builtin contract
    pub cip62: BlockNumber,
    /// CIP64: Get current epoch number through internal contract
    pub cip64: BlockNumber,
    /// CIP71: Configurable anti-reentrancy
    pub cip71: BlockNumber,
    /// CIP78: Correct `is_sponsored` fields in receipt
    pub cip78a: BlockNumber,
    /// CIP78: Correct `is_sponsored` fields in receipt
    pub cip78b: BlockNumber,
    /// CIP90: Two Space for Transaction Execution
    pub cip90b: BlockNumber,
    /// CIP92: Enable Blake2F builtin function
    pub cip92: BlockNumber,
    /// CIP-94: On-chain Parameter DAO Vote
    pub cip94: BlockNumber,
    /// CIP-97: Remove Staking List
    pub cip97: BlockNumber,
    /// CIP-98: Fix BLOCKHASH in espace
    pub cip98: BlockNumber,
    /// CIP-105: PoS staking based minimal votes.
    pub cip105: BlockNumber,
    /// CIP-107: Reduce the refunded storage collateral.
    pub cip107: BlockNumber,
    pub cip_sigma_fix: BlockNumber,
    /// CIP-118: Query Unused Storage Points in Internal Contract
    pub cip118: BlockNumber,
    /// CIP-119: PUSH0 instruction
    pub cip119: BlockNumber,
}

#[derive(Default, Debug, Clone)]
pub struct TransitionsEpochHeight {
    /// The height to change block base reward.
    /// The block `custom` field of this height is required to be
    /// `tanzanite_transition_header_custom`.
    pub cip40: BlockHeight,
    /// CIP76: Remove VM-related constraints in syncing blocks
    pub cip76: BlockHeight,
    /// CIP86: Difficulty adjustment.
    pub cip86: BlockHeight,
    /// CIP90: Two Space for Transaction Execution
    pub cip90a: BlockHeight,
    /// CIP94 Hardfork enable heights.
    pub cip94: BlockHeight,
    /// CIP112 header custom encoding.
    pub cip112: BlockHeight,
}

impl Default for CommonParams {
    fn default() -> Self {
        let mut base_block_rewards = BTreeMap::new();
        base_block_rewards.insert(0, INITIAL_BASE_MINING_REWARD_IN_UCFX.into());
        CommonParams {
            maximum_extra_data_size: 0x20,
            network_id: 0x1,
            chain_id: ChainIdParamsInner::new_simple(AllChainID::new(1, 1)),
            subprotocol_name: "cfx".into(),
            min_gas_limit: 10_000_000.into(),
            gas_limit_bound_divisor: 0x0400.into(),
            max_transaction_size: 300 * 1024,
            anticone_penalty_ratio: ANTICONE_PENALTY_RATIO,
            base_block_rewards,
            evm_transaction_block_ratio: EVM_TRANSACTION_BLOCK_RATIO,
            evm_transaction_gas_ratio: EVM_TRANSACTION_GAS_RATIO,
            params_dao_vote_period: DAO_PARAMETER_VOTE_PERIOD,
            early_set_internal_contracts_states: false,
            transition_numbers: Default::default(),
            transition_heights: Default::default(),
        }
    }
}

impl CommonParams {
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
        if height >= self.transition_heights.cip40
            && height < self.transition_heights.cip94
        {
            Some(vec![TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else if height >= self.transition_heights.cip94
            && height < self.transition_heights.cip112
        {
            Some(vec![DAO_VOTE_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else if height >= self.transition_heights.cip112 {
            Some(vec![CIP112_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else {
            None
        }
    }

    pub fn spec(&self, number: BlockNumber) -> vm::Spec {
        vm::Spec::new_spec_from_common_params(&self, number)
    }

    pub fn can_pack_evm_transaction(&self, height: BlockHeight) -> bool {
        height % self.evm_transaction_block_ratio == 0
    }
}
