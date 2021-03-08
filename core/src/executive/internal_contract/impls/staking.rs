// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus_internal_parameters::MINED_BLOCK_COUNT_PER_QUARTER,
    trace::{trace::ExecTrace, Tracer},
    vm::{self, ActionParams, Env},
};
use cfx_parameters::{
    consensus::ONE_CFX_IN_DRIP,
    internal_contract_addresses::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
};
use cfx_state::state_trait::StateOpsTrait;
use cfx_types::{Address, U256};

/// Implementation of `deposit(uint256)`.
pub fn deposit(
    amount: U256, params: &ActionParams, env: &Env,
    state: &mut dyn StateOpsTrait, tracer: &mut dyn Tracer<Output = ExecTrace>,
) -> vm::Result<()>
{
    if amount < U256::from(ONE_CFX_IN_DRIP) {
        Err(vm::Error::InternalContract("invalid deposit amount"))
    } else if state.balance(&params.sender)? < amount {
        Err(vm::Error::InternalContract("not enough balance to deposit"))
    } else {
        tracer.prepare_internal_transfer_action(
            params.sender,
            *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            amount,
        );
        state.deposit(&params.sender, &amount, env.number)?;
        Ok(())
    }
}

/// Implementation of `withdraw(uint256)`.
pub fn withdraw(
    amount: U256, params: &ActionParams, env: &Env,
    state: &mut dyn StateOpsTrait, tracer: &mut dyn Tracer<Output = ExecTrace>,
) -> vm::Result<()>
{
    state.remove_expired_vote_stake_info(&params.sender, env.number)?;
    if state.withdrawable_staking_balance(&params.sender, env.number)? < amount
    {
        Err(vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw",
        ))
    } else {
        tracer.prepare_internal_transfer_action(
            *STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            params.sender,
            amount,
        );
        let interest_amount = state.withdraw(&params.sender, &amount)?;
        tracer.prepare_internal_transfer_action(
            Address::zero(),
            params.sender,
            interest_amount,
        );
        Ok(())
    }
}

/// Implementation of `getVoteLocked(address,uint)`.
pub fn vote_lock(
    amount: U256, unlock_block_number: U256, params: &ActionParams, env: &Env,
    state: &mut dyn StateOpsTrait,
) -> vm::Result<()>
{
    let unlock_block_number = unlock_block_number.low_u64();
    if unlock_block_number <= env.number {
        Err(vm::Error::InternalContract("invalid unlock_block_number"))
    } else if state.staking_balance(&params.sender)? < amount {
        Err(vm::Error::InternalContract(
            "not enough staking balance to lock",
        ))
    } else {
        state.remove_expired_vote_stake_info(&params.sender, env.number)?;
        state.vote_lock(&params.sender, &amount, unlock_block_number)?;
        Ok(())
    }
}

/// Implementation of `getLockedStakingBalance(address,uint)`.
pub fn get_locked_staking(
    address: Address, block_number: U256, current_block_number: u64,
    state: &mut dyn StateOpsTrait,
) -> vm::Result<U256>
{
    let mut block_number = block_number.low_u64();
    if block_number < current_block_number {
        block_number = current_block_number;
    }
    Ok(state.locked_staking_balance_at_block_number(&address, block_number)?)
}

/// Implementation of `getVotePower(address,uint)`.
pub fn get_vote_power(
    address: Address, block_number: U256, current_block_number: u64,
    state: &mut dyn StateOpsTrait,
) -> vm::Result<U256>
{
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
