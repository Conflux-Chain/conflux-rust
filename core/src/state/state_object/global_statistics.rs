use super::State;
use crate::spec::genesis::{
    genesis_contract_address_four_year, genesis_contract_address_two_year,
};
use cfx_parameters::staking::INTEREST_RATE_PER_BLOCK_SCALE;
use cfx_statedb::{global_params::*, Result as DbResult};
use cfx_types::{Address, AddressSpaceUtil, U256};
impl State {
    /// Calculate the secondary reward for the next block number.
    pub fn bump_block_number_accumulate_interest(&mut self) {
        assert!(self.global_stat_checkpoints.get_mut().is_empty());
        let interset_rate_per_block = self.global_stat.get::<InterestRate>();
        let accumulate_interest_rate =
            self.global_stat.val::<AccumulateInterestRate>();
        *accumulate_interest_rate = *accumulate_interest_rate
            * (*INTEREST_RATE_PER_BLOCK_SCALE + interset_rate_per_block)
            / *INTEREST_RATE_PER_BLOCK_SCALE;
    }

    pub fn secondary_reward(&self) -> U256 {
        assert!(self.global_stat_checkpoints.read().is_empty());
        let secondary_reward = *self.global_stat.refr::<TotalStorage>()
            * *self.global_stat.refr::<InterestRate>()
            / *INTEREST_RATE_PER_BLOCK_SCALE;
        // TODO: the interest from tokens other than storage and staking should
        // send to public fund.
        secondary_reward
    }

    pub fn pow_base_reward(&self) -> U256 {
        let base_reward = self.global_stat.get::<PowBaseReward>();
        assert!(!base_reward.is_zero());
        base_reward
    }

    pub fn total_issued_tokens(&self) -> U256 {
        self.global_stat.get::<TotalIssued>()
    }

    /// Maintain `total_issued_tokens`.
    pub fn add_total_issued(&mut self, v: U256) {
        *self.global_stat.val::<TotalIssued>() += v;
    }

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    pub fn sub_total_issued(&mut self, v: U256) {
        *self.global_stat.val::<TotalIssued>() =
            self.global_stat.refr::<TotalIssued>().saturating_sub(v);
    }

    pub fn add_total_pos_staking(&mut self, v: U256) {
        *self.global_stat.val::<TotalPosStaking>() += v;
    }

    pub fn add_total_evm_tokens(&mut self, v: U256) {
        *self.global_stat.val::<TotalEvmToken>() += v;
    }

    pub fn sub_total_evm_tokens(&mut self, v: U256) {
        *self.global_stat.val::<TotalEvmToken>() =
            self.global_stat.refr::<TotalEvmToken>().saturating_sub(v);
    }

    pub fn total_staking_tokens(&self) -> U256 {
        self.global_stat.get::<TotalStaking>()
    }

    pub fn total_storage_tokens(&self) -> U256 {
        self.global_stat.get::<TotalStorage>()
    }

    pub fn total_espace_tokens(&self) -> U256 {
        self.global_stat.get::<TotalEvmToken>()
    }

    pub fn used_storage_points(&self) -> U256 {
        self.global_stat.get::<UsedStoragePoints>()
    }

    pub fn converted_storage_points(&self) -> U256 {
        self.global_stat.get::<ConvertedStoragePoints>()
    }

    pub fn total_pos_staking_tokens(&self) -> U256 {
        self.global_stat.get::<TotalPosStaking>()
    }

    pub fn sub_total_pos_staking(&mut self, v: U256) {
        *self.global_stat.val::<TotalPosStaking>() =
            self.global_stat.refr::<TotalPosStaking>().saturating_sub(v)
    }

    pub fn distributable_pos_interest(&self) -> U256 {
        self.global_stat.get::<DistributablePoSInterest>()
    }

    pub fn last_distribute_block(&self) -> u64 {
        self.global_stat.refr::<LastDistributeBlock>().as_u64()
    }

    pub fn total_circulating_tokens(&self) -> DbResult<U256> {
        Ok(self.total_issued_tokens()
            - self.balance(&Address::zero().with_native_space())?
            - self.balance(&genesis_contract_address_four_year())?
            - self.balance(&genesis_contract_address_two_year())?)
    }

    pub fn reset_pos_distribute_info(&mut self, current_block_number: u64) {
        *self.global_stat.val::<DistributablePoSInterest>() = U256::zero();
        *self.global_stat.val::<LastDistributeBlock>() =
            U256::from(current_block_number);
    }

    pub fn add_converted_storage_point(
        &mut self, from_balance: U256, from_collateral: U256,
    ) {
        *self.global_stat.val::<TotalIssued>() -=
            from_balance + from_collateral;
        *self.global_stat.val::<TotalStorage>() -= from_collateral;
        *self.global_stat.val::<UsedStoragePoints>() += from_collateral;
        *self.global_stat.val::<ConvertedStoragePoints>() +=
            from_balance + from_collateral;
    }
}
