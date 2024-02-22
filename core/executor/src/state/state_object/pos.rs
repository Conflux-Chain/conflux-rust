// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::State;
use crate::{
    internal_contract::{pos_internal_entries, IndexStatus},
    return_if,
    state::CleanupMode,
};
use cfx_math::sqrt_u256;
use cfx_parameters::{
    internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS, staking::*,
};
use cfx_statedb::{
    global_params::{
        DistributablePoSInterest, InterestRate, LastDistributeBlock,
        TotalPosStaking,
    },
    Result as DbResult,
};
use cfx_types::{Address, AddressSpaceUtil, BigEndianHash, H256, U256};
use diem_types::term_state::MAX_TERM_POINTS;

impl State {
    pub fn inc_distributable_pos_interest(
        &mut self, current_block_number: u64,
    ) -> DbResult<()> {
        assert!(self.checkpoints.get_mut().is_empty());

        let next_distribute_block =
            self.global_stat.refr::<LastDistributeBlock>().as_u64()
                + BLOCKS_PER_HOUR;

        return_if!(current_block_number > next_distribute_block);
        return_if!(self.global_stat.refr::<TotalPosStaking>().is_zero());

        let total_circulating_tokens = self.total_circulating_tokens()?;
        let total_pos_staking_tokens =
            self.global_stat.refr::<TotalPosStaking>();

        // The `interest_amount` exactly equals to the floor of
        // pos_amount * 4% / blocks_per_year / sqrt(pos_amount/total_issued)
        let interest_rate_per_block = self.global_stat.refr::<InterestRate>();
        let interest_amount = sqrt_u256(
            total_circulating_tokens
                * *total_pos_staking_tokens
                * *interest_rate_per_block
                * *interest_rate_per_block,
        ) / (BLOCKS_PER_YEAR
            * INVERSE_INTEREST_RATE
            * INITIAL_INTEREST_RATE_PER_BLOCK.as_u64());
        *self.global_stat.val::<DistributablePoSInterest>() += interest_amount;

        Ok(())
    }

    pub fn pos_locked_staking(&self, address: &Address) -> DbResult<U256> {
        let identifier = BigEndianHash::from_uint(&self.storage_at(
            &POS_REGISTER_CONTRACT_ADDRESS.with_native_space(),
            &pos_internal_entries::identifier_entry(address),
        )?);
        let current_value: IndexStatus = self
            .storage_at(
                &POS_REGISTER_CONTRACT_ADDRESS.with_native_space(),
                &pos_internal_entries::index_entry(&identifier),
            )?
            .into();
        Ok(*POS_VOTE_PRICE * current_value.locked())
    }

    pub fn add_pos_interest(
        &mut self, address: &Address, interest: &U256,
        cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        let address = address.with_native_space();
        self.add_total_issued(*interest);
        self.add_balance(&address, interest, cleanup_mode)?;
        self.write_account_or_new_lock(&address)?
            .record_interest_receive(interest);
        Ok(())
    }
}

/// Distribute PoS interest to the PoS committee according to their reward
/// points. Return the rewarded PoW accounts and their rewarded
/// interest.
pub fn distribute_pos_interest<'a, I>(
    state: &mut State, pos_points: I, current_block_number: u64,
) -> DbResult<Vec<(Address, H256, U256)>>
where I: Iterator<Item = (&'a H256, u64)> + 'a {
    assert!(state.checkpoints.get_mut().is_empty());

    let distributable_pos_interest = state.distributable_pos_interest();

    let mut account_rewards = Vec::new();
    for (identifier, points) in pos_points {
        let address_value = state.storage_at(
            &POS_REGISTER_CONTRACT_ADDRESS.with_native_space(),
            &pos_internal_entries::address_entry(&identifier),
        )?;
        let address = Address::from(H256::from_uint(&address_value));
        let interest = distributable_pos_interest * points / MAX_TERM_POINTS;
        account_rewards.push((address, *identifier, interest));
        state.add_pos_interest(
            &address,
            &interest,
            CleanupMode::ForceCreate, /* Same as distributing block
                                       * reward. */
        )?;
    }
    state.reset_pos_distribute_info(current_block_number);

    Ok(account_rewards)
}

pub fn update_pos_status(
    state: &mut State, identifier: H256, number: u64,
) -> DbResult<()> {
    let old_value = state.storage_at(
        &POS_REGISTER_CONTRACT_ADDRESS.with_native_space(),
        &pos_internal_entries::index_entry(&identifier),
    )?;
    assert!(
        !old_value.is_zero(),
        "If an identifier is unlocked, its index information must be non-zero"
    );
    let mut status: IndexStatus = old_value.into();
    let new_unlocked = number - status.unlocked;
    status.set_unlocked(number);
    // .expect("Incorrect unlock information");
    state
        .write_native_account_lock(&POS_REGISTER_CONTRACT_ADDRESS)?
        .change_storage_value(
            &state.db,
            &pos_internal_entries::index_entry(&identifier),
            status.into(),
        )?;
    state.sub_total_pos_staking(*POS_VOTE_PRICE * new_unlocked);
    Ok(())
}
