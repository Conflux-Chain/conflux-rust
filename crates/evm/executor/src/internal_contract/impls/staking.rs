// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive_observer::{AddressPocket, TracerTrait},
    internal_bail,
    state::State,
};
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP,
    consensus_internal::MINED_BLOCK_COUNT_PER_QUARTER,
};
use cfx_types::{Address, AddressSpaceUtil, U256};
use cfx_vm_types::{self as vm, ActionParams, Env, Spec};

/// Implementation of `deposit(uint256)`.
pub fn deposit(
    amount: U256, params: &ActionParams, env: &Env, spec: &Spec,
    state: &mut State, tracer: &mut dyn TracerTrait,
) -> vm::Result<()> {
    if amount < U256::from(ONE_CFX_IN_DRIP) {
        internal_bail!("invalid deposit amount");
    }

    if state.balance(&params.sender.with_native_space())? < amount {
        internal_bail!("not enough balance to deposit");
    }

    tracer.trace_internal_transfer(
        AddressPocket::Balance(params.sender.with_space(params.space)),
        AddressPocket::StakingBalance(params.sender),
        amount,
    );
    state.deposit(&params.sender, &amount, env.number, spec.cip97)?;
    Ok(())
}

/// Implementation of `withdraw(uint256)`.
pub fn withdraw(
    amount: U256, params: &ActionParams, env: &Env, spec: &Spec,
    state: &mut State, tracer: &mut dyn TracerTrait,
) -> vm::Result<()> {
    state.remove_expired_vote_stake_info(&params.sender, env.number)?;
    if state.withdrawable_staking_balance(&params.sender, env.number)? < amount
    {
        internal_bail!("not enough withdrawable staking balance to withdraw");
    }

    if state.staking_balance(&params.sender)? - amount
        < state.pos_locked_staking(&params.sender)?
    {
        internal_bail!("not enough unlocked staking balance to withdraw");
    }

    tracer.trace_internal_transfer(
        AddressPocket::StakingBalance(params.sender),
        AddressPocket::Balance(params.sender.with_space(params.space)),
        amount,
    );
    let interest_amount =
        state.withdraw(&params.sender, &amount, spec.cip97)?;
    tracer.trace_internal_transfer(
        AddressPocket::MintBurn,
        AddressPocket::Balance(params.sender.with_space(params.space)),
        interest_amount,
    );
    Ok(())
}

/// Implementation of `getVoteLocked(address,uint)`.
pub fn vote_lock(
    amount: U256, unlock_block_number: U256, params: &ActionParams, env: &Env,
    state: &mut State,
) -> vm::Result<()> {
    let unlock_block_number = unlock_block_number.low_u64();
    if unlock_block_number <= env.number {
        internal_bail!("invalid unlock_block_number");
    }
    if state.staking_balance(&params.sender)? < amount {
        internal_bail!("not enough staking balance to lock");
    }

    state.remove_expired_vote_stake_info(&params.sender, env.number)?;
    state.vote_lock(&params.sender, &amount, unlock_block_number)?;
    Ok(())
}

/// Implementation of `getLockedStakingBalance(address,uint)`.
pub fn get_locked_staking(
    address: Address, block_number: U256, current_block_number: u64,
    state: &mut State,
) -> vm::Result<U256> {
    let mut block_number = block_number.low_u64();
    if block_number < current_block_number {
        block_number = current_block_number;
    }
    Ok(state.locked_staking_balance_at_block_number(&address, block_number)?)
}

/// Implementation of `getVotePower(address,uint)`.
pub fn get_vote_power(
    address: Address, block_number: U256, current_block_number: u64,
    state: &mut State,
) -> vm::Result<U256> {
    let mut block_number = block_number.low_u64();
    if block_number < current_block_number {
        block_number = current_block_number;
    }

    let three_months_locked = state.locked_staking_balance_at_block_number(
        &address,
        block_number + MINED_BLOCK_COUNT_PER_QUARTER,
    )?;
    let six_months_locked = state.locked_staking_balance_at_block_number(
        &address,
        block_number + 2 * MINED_BLOCK_COUNT_PER_QUARTER,
    )?;
    let one_year_locked = state.locked_staking_balance_at_block_number(
        &address,
        block_number + 4 * MINED_BLOCK_COUNT_PER_QUARTER,
    )?;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━
    //              Remaining Committed Staking Time             ┃  Voting Power
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━
    // One year or more (i.e. ≥ 63072000 blocks)                 ┃    1
    // Six months to one year (≥ 31536000 but < 63072000 blocks) ┃    0.5
    // Three to six months (≥ 15768000 but < 31536000 blocks)    ┃    0.25
    // Less than three month (i.e. < 15768000 blocks)            ┃    0
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━
    let vote_power =
        (three_months_locked + six_months_locked + one_year_locked * 2) / 4;
    Ok(vote_power)
}
