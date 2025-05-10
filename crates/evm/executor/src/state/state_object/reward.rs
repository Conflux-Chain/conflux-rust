use super::State;
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP, consensus_internal::CIP137_BASEFEE_PROP_INIT,
};
use cfx_types::U256;

use cfx_parameters::staking::INTEREST_RATE_PER_BLOCK_SCALE;
use cfx_statedb::global_params::*;

impl State {
    /// Calculate the secondary reward for the next block number.
    pub fn bump_block_number_accumulate_interest(&mut self) {
        assert!(self.no_checkpoint());
        let interset_rate_per_block = self.global_stat.get::<InterestRate>();
        let accumulate_interest_rate =
            self.global_stat.val::<AccumulateInterestRate>();
        *accumulate_interest_rate = *accumulate_interest_rate
            * (*INTEREST_RATE_PER_BLOCK_SCALE + interset_rate_per_block)
            / *INTEREST_RATE_PER_BLOCK_SCALE;
    }

    pub fn secondary_reward(&self) -> U256 {
        assert!(self.no_checkpoint());
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

    pub fn distributable_pos_interest(&self) -> U256 {
        self.global_stat.get::<DistributablePoSInterest>()
    }

    pub fn last_distribute_block(&self) -> u64 {
        self.global_stat.refr::<LastDistributeBlock>().as_u64()
    }

    pub fn reset_pos_distribute_info(&mut self, current_block_number: u64) {
        *self.global_stat.val::<DistributablePoSInterest>() = U256::zero();
        *self.global_stat.val::<LastDistributeBlock>() =
            U256::from(current_block_number);
    }

    pub fn burn_by_cip1559(&mut self, by: U256) {
        // This function is called after transaction exeuction. At this time,
        // the paid transaction fee has already been in the core space.
        *self.global_stat.val::<TotalBurnt1559>() += by;
        self.sub_total_issued(by);
    }

    pub fn get_base_price_prop(&self) -> U256 {
        self.global_stat.get::<BaseFeeProp>()
    }

    pub fn set_base_fee_prop(&mut self, val: U256) {
        *self.global_stat.val::<BaseFeeProp>() = val;
    }

    pub fn burnt_gas_price(&self, base_price: U256) -> U256 {
        if base_price.is_zero() {
            return U256::zero();
        }
        let prop = self.get_base_price_prop();
        base_price - base_price * prop / (U256::from(ONE_CFX_IN_DRIP) + prop)
    }
}

/// Initialize CIP-137 for the whole system.
pub fn initialize_cip137(state: &mut State) {
    debug!("set base_fee_prop to {}", CIP137_BASEFEE_PROP_INIT);
    state.set_base_fee_prop(CIP137_BASEFEE_PROP_INIT.into());
}
