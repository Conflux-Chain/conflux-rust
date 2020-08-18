// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    state::State,
    vm::{self, ActionParams},
};
use cfx_parameters::consensus::ONE_CFX_IN_DRIP;
use cfx_types::U256;

/// Implementation of `deposit(uint256)`.
/// The input should consist of 32 bytes `amount`.
pub fn deposit(
    amount: U256, params: &ActionParams, state: &mut State,
) -> vm::Result<()> {
    if amount < U256::from(ONE_CFX_IN_DRIP) {
        Err(vm::Error::InternalContract("invalid deposit amount"))
    } else if state.balance(&params.sender)? < amount {
        Err(vm::Error::InternalContract("not enough balance to deposit"))
    } else {
        state.deposit(&params.sender, &amount)?;
        Ok(())
    }
}

/// Implementation of `withdraw(uint256)`.
/// The input should consist of 32 bytes `amount`.
pub fn withdraw(
    amount: U256, params: &ActionParams, state: &mut State,
) -> vm::Result<()> {
    state.remove_expired_vote_stake_info(&params.sender)?;
    if state.withdrawable_staking_balance(&params.sender)? < amount {
        Err(vm::Error::InternalContract(
            "not enough withdrawable staking balance to withdraw",
        ))
    } else {
        state.withdraw(&params.sender, &amount)?;
        Ok(())
    }
}

/// Implementation of `lock(uint256,uint256)`.
/// The input should consist of 32 bytes `amount` + 32 bytes
/// `unlock_block_number`.
pub fn vote_lock(
    amount: U256, unlock_block_number: U256, params: &ActionParams,
    state: &mut State,
) -> vm::Result<()>
{
    let unlock_block_number = unlock_block_number.low_u64();
    if unlock_block_number <= state.block_number() {
        Err(vm::Error::InternalContract("invalid unlock_block_number"))
    } else if state.staking_balance(&params.sender)? < amount {
        Err(vm::Error::InternalContract(
            "not enough staking balance to lock",
        ))
    } else {
        state.remove_expired_vote_stake_info(&params.sender)?;
        state.vote_lock(&params.sender, &amount, unlock_block_number)?;
        Ok(())
    }
}
