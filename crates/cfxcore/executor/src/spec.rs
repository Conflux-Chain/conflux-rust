// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_bytes::Bytes;
use cfx_internal_common::{ChainIdParams, ChainIdParamsInner};
use cfx_parameters::{
    block::{EVM_TRANSACTION_BLOCK_RATIO, EVM_TRANSACTION_GAS_RATIO},
    consensus::{
        CIP112_HEADER_CUSTOM_FIRST_ELEMENT,
        DAO_VOTE_HEADER_CUSTOM_FIRST_ELEMENT,
        NEXT_HARDFORK_HEADER_CUSTOM_FIRST_ELEMENT, ONE_UCFX_IN_DRIP,
        TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT,
    },
    consensus_internal::{
        ANTICONE_PENALTY_RATIO, DAO_PARAMETER_VOTE_PERIOD,
        INITIAL_BASE_MINING_REWARD_IN_UCFX,
    },
};
use cfx_types::{AllChainID, Space, SpaceMap, U256, U512};
use cfx_vm_types::Spec;
use primitives::{block::BlockHeight, BlockNumber};
use std::collections::BTreeMap;

// FIXME: This type is mainly used for execution layer parameters, but some
// consensus layer parameters and functions are also inappropriately placed
// here.

#[derive(Debug, Clone)]
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
    pub min_base_price: SpaceMap<U256>,

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
    /// CIP-43: Introduce Finality Through Staking Vote
    pub cip43a: BlockNumber,
    pub cip43b: BlockNumber,
    /// CIP-62: Enable EC-Related Builtin Contracts
    pub cip62: BlockNumber,
    /// CIP-64: Get Current Epoch Number via Internal Contract
    pub cip64: BlockNumber,
    /// CIP-71: Disable Anti-Reentrancy
    pub cip71: BlockNumber,
    /// CIP-78: Correct `is_sponsored` Fields in Receipt
    pub cip78a: BlockNumber,
    pub cip78b: BlockNumber,
    /// CIP-90: Introduce a Fully EVM-Compatible Space
    pub cip90b: BlockNumber,
    /// CIP-92: Enable Blake2F Builtin Function
    pub cip92: BlockNumber,
    /// CIP-94: On-Chain DAO Vote for Chain Parameters
    pub cip94n: BlockNumber,
    /// CIP-97: Clear Staking Lists
    pub cip97: BlockNumber,
    /// CIP-98: Fix BLOCKHASH Opcode Bug in eSpace
    pub cip98: BlockNumber,
    /// CIP-105: Minimal DAO Vote Count Based on PoS Staking
    pub cip105: BlockNumber,
    /// CIP-107: DAO-Adjustable Burn of Storage Collateral
    pub cip107: BlockNumber,
    /// A security fix without a publicly submitted CIP
    pub cip_sigma_fix: BlockNumber,
    /// CIP-118: Query Unused Storage Points in Internal Contract
    pub cip118: BlockNumber,
    /// CIP-119: PUSH0 instruction
    pub cip119: BlockNumber,
    /// CIP-131: Retain Whitelist on Contract Deletion
    pub cip131: BlockNumber,
    /// CIP-132: Fix Static Context Check for Internal Contracts
    pub cip132: BlockNumber,
    /// CIP-133: Enhanced Block Hash Query
    pub cip133b: BlockNumber,
    /// CIP-137: Base Fee Sharing in CIP-1559
    pub cip137: BlockNumber,
    /// CIP-141: Disable Subroutine Opcodes
    /// CIP-142: Transient Storage Opcodes
    /// CIP-143: MCOPY (0x5e) Opcode for Efficient Memory Copy
    pub cancun_opcodes: BlockNumber,
    /// CIP-144: Point Evaluation Precompile from EIP-4844
    pub cip144: BlockNumber,
    /// CIP-145: Fix Receipts upon `NotEnoughBalance` Error
    pub cip145: BlockNumber,
}

#[derive(Default, Debug, Clone)]
pub struct TransitionsEpochHeight {
    /// CIP-40: Reduce Block Base Reward to 2 CFX
    pub cip40: BlockHeight,
    /// CIP-76: Remove VM-Related Constraints in Syncing Blocks
    pub cip76: BlockHeight,
    /// CIP-86: Update Difficulty Adjustment Algorithm
    pub cip86: BlockHeight,
    /// CIP-90: Introduce a Fully EVM-Compatible Space
    pub cip90a: BlockHeight,
    /// CIP-94: On-Chain DAO Vote for Chain Parameters
    pub cip94h: BlockHeight,
    /// CIP-112: Fix Block Headers `custom` Field Serde
    pub cip112: BlockHeight,
    /// CIP-130: Aligning Gas Limit with Transaction Size
    pub cip130: BlockHeight,
    /// CIP-133: Enhanced Block Hash Query
    pub cip133e: BlockHeight,
    pub cip1559: BlockHeight,
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
            min_base_price: SpaceMap::default(),
        }
    }
}

impl CommonParams {
    pub fn spec(&self, number: BlockNumber, height: BlockHeight) -> Spec {
        let mut spec = Spec::genesis_spec();
        spec.cip43_contract = number >= self.transition_numbers.cip43a;
        spec.cip43_init = number >= self.transition_numbers.cip43a
            && number < self.transition_numbers.cip43b;
        spec.cip62 = number >= self.transition_numbers.cip62;
        spec.cip64 = number >= self.transition_numbers.cip64;
        spec.cip71 = number >= self.transition_numbers.cip71;
        spec.cip90 = number >= self.transition_numbers.cip90b;
        spec.cip78a = number >= self.transition_numbers.cip78a;
        spec.cip78b = number >= self.transition_numbers.cip78b;
        spec.cip94 = number >= self.transition_numbers.cip94n;
        spec.cip94_activation_block_number = self.transition_numbers.cip94n;
        spec.cip97 = number >= self.transition_numbers.cip97;
        spec.cip98 = number >= self.transition_numbers.cip98;
        spec.cip105 = number >= self.transition_numbers.cip105;
        spec.cip_sigma_fix = number >= self.transition_numbers.cip_sigma_fix;
        spec.params_dao_vote_period = self.params_dao_vote_period;
        spec.cip107 = number >= self.transition_numbers.cip107;
        spec.cip118 = number >= self.transition_numbers.cip118;
        spec.cip119 = number >= self.transition_numbers.cip119;
        spec.cip131 = number >= self.transition_numbers.cip131;
        spec.cip132 = number >= self.transition_numbers.cip132;
        spec.cip133_b = self.transition_numbers.cip133b;
        spec.cip133_e = self.transition_heights.cip133e;
        spec.cip133_core = number >= self.transition_numbers.cip133b;
        spec.cip137 = number >= self.transition_numbers.cip137;
        spec.cip144 = number >= self.transition_numbers.cip144;
        spec.cip145 = number >= self.transition_numbers.cip145;
        spec.cip1559 = height >= self.transition_heights.cip1559;
        spec.cancun_opcodes = number >= self.transition_numbers.cancun_opcodes;
        if spec.cancun_opcodes {
            spec.sload_gas = 800;
        }
        spec
    }

    #[cfg(test)]
    pub fn spec_for_test(&self, number: u64) -> Spec {
        self.spec(number, number)
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
        if height >= self.transition_heights.cip40
            && height < self.transition_heights.cip94h
        {
            Some(vec![TANZANITE_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else if height >= self.transition_heights.cip94h
            && height < self.transition_heights.cip112
        {
            Some(vec![DAO_VOTE_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else if height >= self.transition_heights.cip112
            && height < self.transition_heights.cip1559
        {
            Some(vec![CIP112_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else if height >= self.transition_heights.cip1559 {
            Some(vec![NEXT_HARDFORK_HEADER_CUSTOM_FIRST_ELEMENT.to_vec()])
        } else {
            None
        }
    }

    pub fn can_pack_evm_transaction(&self, height: BlockHeight) -> bool {
        height % self.evm_transaction_block_ratio == 0
    }

    pub fn chain_id(&self, epoch_height: u64, space: Space) -> u32 {
        self.chain_id
            .read()
            .get_chain_id(epoch_height)
            .in_space(space)
    }

    pub fn chain_id_map(&self, epoch_height: u64) -> BTreeMap<Space, u32> {
        BTreeMap::from([
            (Space::Native, self.chain_id(epoch_height, Space::Native)),
            (
                Space::Ethereum,
                self.chain_id(epoch_height, Space::Ethereum),
            ),
        ])
    }

    pub fn init_base_price(&self) -> SpaceMap<U256> { self.min_base_price }

    pub fn min_base_price(&self) -> SpaceMap<U256> { self.min_base_price }
}
