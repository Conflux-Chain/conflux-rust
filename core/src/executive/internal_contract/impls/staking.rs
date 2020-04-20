// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    bytes::Bytes,
    parameters::staking::*,
    state::{State, Substate},
    vm::{self, ActionParams, CallType, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS: Address =
        Address::from_str("843c409373ffd5c0bec1dddb7bec830856757b65").unwrap();
}

pub struct Staking;

impl Staking {
    fn deposit(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
        // FIXME: we should find a reasonable lowerbound.
        if amount < U256::one() {
            Err(vm::Error::InternalContract("invalid deposit amount"))
        } else if state.balance(&params.sender)? < amount {
            Err(vm::Error::InternalContract("not enough balance to deposit"))
        } else {
            state.deposit(&params.sender, &amount)?;
            Ok(())
        }
    }

    fn withdraw(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
        if state.withdrawable_staking_balance(&params.sender)? < amount {
            Err(vm::Error::InternalContract(
                "not enough withdrawable staking balance to withdraw",
            ))
        } else {
            state.withdraw(&params.sender, &amount)?;
            Ok(())
        }
    }

    fn lock(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 64 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let amount = U256::from(&input[0..32]);
        let duration_in_day = U256::from(&input[32..64]).low_u64();
        if duration_in_day == 0
            || duration_in_day
                > (std::u64::MAX - state.block_number()) / BLOCKS_PER_DAY
        {
            Err(vm::Error::InternalContract("invalid lock duration"))
        } else if state.staking_balance(&params.sender)? < amount {
            Err(vm::Error::InternalContract(
                "not enough staking balance to lock",
            ))
        } else {
            state.lock(&params.sender, &amount, duration_in_day)?;
            Ok(())
        }
    }
}

impl InternalContractTrait for Staking {
    /// Address of the internal contract
    fn address(&self) -> &Address { &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS }

    /// The gas cost of running this internal contract for the given input data.
    fn cost(&self, _input: Option<&Bytes>) -> U256 { U256::zero() }

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

        if data[0..4] == [0xb6, 0xb5, 0x5f, 0x25] {
            // The first 4 bytes of
            // keccak('deposit(uint256)') is
            // `0xb6b55f25`.
            // 4 bytes `Method ID` + 32 bytes `amount`
            self.deposit(&data[4..], params, state)
        } else if data[0..4] == [0x2e, 0x1a, 0x7d, 0x4d] {
            // The first 4 bytes of
            // keccak('withdraw(uint256)') is `0x2e1a7d4d`.
            // 4 bytes `Method ID` + 32 bytes `amount`.
            self.withdraw(&data[4..], params, state)
        } else if data[0..4] == [0x13, 0x38, 0x73, 0x6f] {
            // The first 4 bytes of
            // keccak('lock(uint256,uint256)') is `0x1338736f`.
            // 4 bytes `Method ID` + 32 bytes `amount` + 32 bytes
            // `duration_in_day`.
            self.lock(&data[4..], params, state)
        } else {
            Err(vm::Error::InternalContract("unsupported function"))
        }
    }
}
