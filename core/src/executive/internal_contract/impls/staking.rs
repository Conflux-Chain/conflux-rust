// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    parameters::consensus::ONE_CFX_IN_DRIP,
    state::{State, Substate},
    vm::{self, ActionParams, CallType, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000002").unwrap();
}

/// The first 4 bytes of keccak('deposit(uint256)') is `0xb6b55f25`.
static DEPOSIT_SIG: &'static [u8] = &[0xb6, 0xb5, 0x5f, 0x25];
/// The first 4 bytes of keccak('withdraw(uint256)') is `0x2e1a7d4d`.
static WITHDRAW_SIG: &'static [u8] = &[0x2e, 0x1a, 0x7d, 0x4d];
/// The first 4 bytes of keccak('vote_lock(uint256,uint256)') is `0x5547dedb`.
static VOTE_LOCK_SIG: &'static [u8] = &[0x55, 0x47, 0xde, 0xdb];

pub struct Staking;

impl Staking {
    /// Implementation of `deposit(uint256)`.
    /// The input should consist of 32 bytes `amount`.
    fn deposit(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
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
    fn withdraw(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
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
    fn vote_lock(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 64 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
        let unlock_block_number = U256::from(&input[32..64]).low_u64();
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
}

impl InternalContractTrait for Staking {
    /// Address of the internal contract
    fn address(&self) -> &Address { &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS }

    /// The gas cost of running this internal contract for the given input data.
    ///
    /// + deposit: SSTORE (deposit_balance, deposit_time)
    ///   Gas: 10000 * (current length of `deposit_list`) + 10000
    /// + withdraw: SLOAD (withdrawable_balance, deposit_time) SSTORE
    ///             (deposit_balance, update new deposit_list)
    ///   Gas: 10000 * (current length of `deposit_list`)
    /// + lock: SSTORE (updating new locking entry and remove unnecessary ones),
    ///         SLOAD (binary search and compare)
    ///   Gas: 10000 * (current length of `vote_stake_list`)
    /// + otherwise
    ///   Gas: 10000
    fn cost(&self, params: &ActionParams, state: &mut State) -> U256 {
        if let Some(ref data) = params.data {
            if data.len() < 4 {
                return U256::from(10000);
            }
            if data[0..4] == *DEPOSIT_SIG {
                let length =
                    state.deposit_list_length(&params.sender).unwrap_or(0);
                U256::from(10000) * U256::from(length + 1)
            } else if data[0..4] == *WITHDRAW_SIG {
                let length =
                    state.deposit_list_length(&params.sender).unwrap_or(0);
                U256::from(10000) * U256::from(length)
            } else if data[0..4] == *VOTE_LOCK_SIG {
                let length =
                    state.vote_stake_list_length(&params.sender).unwrap_or(0);
                U256::from(10000) * U256::from(length + 1)
            } else {
                U256::from(10000)
            }
        } else {
            U256::from(10000)
        }
    }

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, _spec: &Spec, state: &mut State,
        _substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if params.call_type == CallType::StaticCall {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data.len() < 4 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        if &params.address != self.address() {
            return Err(vm::Error::InternalContract(
                "can not delegatecall or callcode internal contract",
            ));
        }

        if !params.value.value().is_zero() {
            return Err(vm::Error::InternalContract(
                "should not transfer balance to Staking contract",
            ));
        }

        if data[0..4] == *DEPOSIT_SIG {
            self.deposit(&data[4..], params, state)
        } else if data[0..4] == *WITHDRAW_SIG {
            self.withdraw(&data[4..], params, state)
        } else if data[0..4] == *VOTE_LOCK_SIG {
            self.vote_lock(&data[4..], params, state)
        } else {
            Err(vm::Error::InternalContract("unsupported function"))
        }
    }
}
