use super::{RequireFields, State};
use crate::{
    internal_contract::{
        get_settled_param_vote_count, get_settled_pos_staking_for_votes,
        settle_current_votes, storage_point_prop,
    },
    return_if, try_loaded,
};
use cfx_parameters::{
    consensus::ONE_UCFX_IN_DRIP,
    consensus_internal::MINING_REWARD_TANZANITE_IN_UCFX,
};
use cfx_statedb::{
    global_params::{
        AccumulateInterestRate, InterestRate, PowBaseReward, TotalStaking,
    },
    Result as DbResult,
};
use cfx_types::{Address, AddressSpaceUtil, U256};

// Staking balance

impl State {
    pub fn staking_balance(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(*acc.staking_balance())
    }

    pub fn withdrawable_staking_balance(
        &self, address: &Address, current_block_number: u64,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_ext_lock(
            &address.with_native_space(),
            RequireFields::VoteStakeList,
        ));
        Ok(acc.withdrawable_staking_balance(current_block_number))
    }

    pub fn locked_staking_balance_at_block_number(
        &self, address: &Address, block_number: u64,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_ext_lock(
            &address.with_native_space(),
            RequireFields::VoteStakeList,
        ));
        Ok(acc.staking_balance()
            - acc.withdrawable_staking_balance(block_number))
    }

    pub fn vote_stake_list_length(&self, address: &Address) -> DbResult<usize> {
        let acc = try_loaded!(self.read_account_ext_lock(
            &address.with_native_space(),
            RequireFields::VoteStakeList
        ));
        Ok(acc.vote_stake_list().len())
    }

    pub fn vote_lock(
        &mut self, address: &Address, amount: &U256, unlock_block_number: u64,
    ) -> DbResult<()> {
        return_if!(amount.is_zero());

        self.write_account_ext_lock(
            &address.with_native_space(),
            RequireFields::VoteStakeList,
        )?
        .vote_lock(*amount, unlock_block_number);
        Ok(())
    }

    pub fn remove_expired_vote_stake_info(
        &mut self, address: &Address, current_block_number: u64,
    ) -> DbResult<()> {
        let mut account = self.write_native_account_lock(&address)?;
        account.cache_ext_fields(false, true, &self.db)?;
        account.remove_expired_vote_stake_info(current_block_number);
        Ok(())
    }

    pub fn deposit_list_length(&self, address: &Address) -> DbResult<usize> {
        let acc = try_loaded!(self.read_account_ext_lock(
            &address.with_native_space(),
            RequireFields::DepositList
        ));
        Ok(acc.deposit_list().len())
    }

    pub fn deposit(
        &mut self, address: &Address, amount: &U256, current_block_number: u64,
        cip_97: bool,
    ) -> DbResult<()> {
        return_if!(amount.is_zero());

        let acc_interest_rate =
            self.global_stat.get::<AccumulateInterestRate>();
        self.write_account_ext_lock(
            &address.with_native_space(),
            RequireFields::DepositList,
        )?
        .deposit(
            *amount,
            acc_interest_rate,
            current_block_number,
            cip_97,
        );
        *self.global_stat.val::<TotalStaking>() += *amount;
        Ok(())
    }

    pub fn withdraw(
        &mut self, address: &Address, amount: &U256, cip_97: bool,
    ) -> DbResult<U256> {
        return_if!(amount.is_zero());

        let accumulated_interest_rate =
            self.global_stat.get::<AccumulateInterestRate>();
        let interest = self
            .write_account_ext_lock(
                &address.with_native_space(),
                RequireFields::DepositList,
            )?
            .withdraw(*amount, accumulated_interest_rate, cip_97);

        // the interest will be put in balance.
        self.add_total_issued(interest);
        *self.global_stat.val::<TotalStaking>() -= *amount;
        Ok(interest)
    }
}

pub fn initialize_or_update_dao_voted_params(
    state: &mut State, cip105: bool,
) -> DbResult<()> {
    let vote_count = get_settled_param_vote_count(state).expect("db error");
    debug!(
        "initialize_or_update_dao_voted_params: vote_count={:?}",
        vote_count
    );
    debug!(
        "before pos interest: {} base_reward:{}",
        state.global_stat.refr::<InterestRate>(),
        state.global_stat.refr::<PowBaseReward>(),
    );

    // If pos_staking has not been set before, this will be zero and the
    // vote count will always be sufficient, so we do not need to
    // check if CIP105 is enabled here.
    let pos_staking_for_votes = get_settled_pos_staking_for_votes(state)?;
    // If the internal contract is just initialized, all votes are zero and
    // the parameters remain unchanged.
    *state.global_stat.val::<InterestRate>() =
        vote_count.pos_reward_interest.compute_next_params(
            state.global_stat.get::<InterestRate>(),
            pos_staking_for_votes,
        );

    // Initialize or update PoW base reward.
    let pow_base_reward = state.global_stat.val::<PowBaseReward>();
    if !pow_base_reward.is_zero() {
        *pow_base_reward = vote_count
            .pow_base_reward
            .compute_next_params(*pow_base_reward, pos_staking_for_votes);
    } else {
        *pow_base_reward =
            (MINING_REWARD_TANZANITE_IN_UCFX * ONE_UCFX_IN_DRIP).into();
    }

    // Only write storage_collateral_refund_ratio if it has been set in the
    // db. This keeps the state unchanged before cip107 is enabled.
    // TODO: better way in check if cip107 encabled.
    let old_storage_point_prop =
        state.get_system_storage(&storage_point_prop())?;
    if !old_storage_point_prop.is_zero() {
        debug!("old_storage_point_prop: {}", old_storage_point_prop);
        state.set_system_storage(
            storage_point_prop().to_vec(),
            vote_count.storage_point_prop.compute_next_params(
                old_storage_point_prop,
                pos_staking_for_votes,
            ),
        )?;
    }

    let old_base_fee_prop = state.get_base_price_prop();
    if !old_base_fee_prop.is_zero() {
        state.set_base_fee_prop(
            vote_count
                .base_fee_prop
                .compute_next_params(old_base_fee_prop, pos_staking_for_votes),
        )
    }
    debug!(
        "pos interest: {} base_reward: {}",
        state.global_stat.refr::<InterestRate>(),
        state.global_stat.refr::<PowBaseReward>()
    );

    settle_current_votes(state, cip105)?;

    Ok(())
}
