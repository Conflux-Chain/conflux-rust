// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    bytes::Bytes,
    state::{State, Substate},
    vm::{self, ActionParams, CallType, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("8ad036480160591706c831f0da19d1a424e39469").unwrap();
}

pub struct SponsorWhitelistControl;

impl SponsorWhitelistControl {
    fn set_sponsor_for_gas(
        &self, input: &[u8], params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if input.len() != 64 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let sponsor = &params.sender;
        let contract_address = Address::from_slice(&input[12..32]);
        let upper_bound = U256::from(&input[32..64]);
        if !state.exists(&contract_address)? {
            return Err(vm::Error::InternalContract(
                "contract address not exist",
            ));
        }

        if !state.is_contract(&contract_address) {
            return Err(vm::Error::InternalContract(
                "not allowed to sponsor non-contract account",
            ));
        }

        let sponsor_balance = state.balance(self.address())?;

        if sponsor_balance / U256::from(1000) < upper_bound {
            return Err(vm::Error::InternalContract(
                "sponsor should at least sponsor upper_bound * 1000",
            ));
        }

        let prev_sponsor = state.sponsor_for_gas(&contract_address)?;
        let prev_sponsor_balance =
            state.sponsor_balance_for_gas(&contract_address)?;
        let prev_upper_bound = state.sponsor_gas_bound(&contract_address)?;
        // If previous sponsor is not the same as current sponsor, we should try
        // to replace the sponsor. Otherwise, we should try to charge
        // `sponsor_balance`.
        if prev_sponsor.as_ref().map_or_else(
            || !sponsor.is_zero(),
            |prev_sponsor| prev_sponsor != sponsor,
        ) {
            // `sponsor_balance` should exceed previous sponsor's
            // `sponsor_balance`.
            if sponsor_balance <= prev_sponsor_balance {
                return Err(vm::Error::InternalContract(
                    "sponsor_balance is not exceed previous sponsor",
                ));
            }
            // `upper_bound` should exceed previous sponsor's `upper_bound`,
            // unless previous sponsor's `sponsor_balance` is not able to cover
            // the upper bound.
            if prev_sponsor_balance >= prev_upper_bound
                && upper_bound <= prev_upper_bound
            {
                return Err(vm::Error::InternalContract(
                    "upper_bound is not exceed previous sponsor",
                ));
            }
            // refund to previous sponsor
            if prev_sponsor.is_some() {
                state.add_balance(
                    prev_sponsor.as_ref().unwrap(),
                    &prev_sponsor_balance,
                    substate.to_cleanup_mode(&spec),
                )?;
            }
            state.sub_balance(
                self.address(),
                &sponsor_balance,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.set_sponsor_for_gas(
                &contract_address,
                sponsor,
                &sponsor_balance,
                &upper_bound,
            )?;
        } else {
            // if previous sponsor's `sponsor_balance` is not able to cover
            // the `upper_bound`, we can adjust the `upper_bound` to a smaller
            // one.
            if prev_sponsor_balance >= prev_upper_bound
                && upper_bound < prev_upper_bound
            {
                return Err(vm::Error::InternalContract(
                    "cannot change upper_bound to a smaller one",
                ));
            }
            state.sub_balance(
                self.address(),
                &sponsor_balance,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.set_sponsor_for_gas(
                &contract_address,
                sponsor,
                &(sponsor_balance + prev_sponsor_balance),
                &upper_bound,
            )?;
        }

        Ok(())
    }

    fn set_sponsor_for_collateral(
        &self, input: &[u8], params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }
        let sponsor = &params.sender;
        let contract_address = Address::from_slice(&input[12..32]);
        if !state.exists(&contract_address)? {
            return Err(vm::Error::InternalContract(
                "contract address not exist",
            ));
        }

        if !state.is_contract(&contract_address) {
            return Err(vm::Error::InternalContract(
                "not allowed to sponsor non-contract account",
            ));
        }

        let sponsor_balance = state.balance(self.address())?;

        if sponsor_balance.is_zero() {
            return Err(vm::Error::InternalContract(
                "zero sponsor balance is not allowed",
            ));
        }

        let prev_sponsor = state.sponsor_for_collateral(&contract_address)?;
        let prev_sponsor_balance =
            state.sponsor_balance_for_collateral(&contract_address)?;
        let collateral_for_storage =
            state.collateral_for_storage(&contract_address)?;
        // If previous sponsor is not the same as current sponsor, we should try
        // to replace the sponsor. Otherwise, we should try to charge
        // `sponsor_balance`.
        if prev_sponsor.as_ref().map_or_else(
            || !sponsor.is_zero(),
            |prev_sponsor| prev_sponsor != sponsor,
        ) {
            // `sponsor_balance` should exceed previous sponsor's
            // `sponsor_balance` + `collateral_for_storage`.
            if sponsor_balance <= prev_sponsor_balance + collateral_for_storage
            {
                return Err(vm::Error::InternalContract(
                    "sponsor_balance is not enough to cover previous sponsor's sponsor_balance and collateral_for_storage",
                ));
            }
            // refund to previous sponsor
            if prev_sponsor.is_some() {
                state.add_balance(
                    prev_sponsor.as_ref().unwrap(),
                    &(prev_sponsor_balance + collateral_for_storage),
                    substate.to_cleanup_mode(&spec),
                )?;
            }
            state.sub_balance(
                self.address(),
                &sponsor_balance,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.set_sponsor_for_collateral(
                &contract_address,
                sponsor,
                &(sponsor_balance - collateral_for_storage),
            )?;
        } else {
            state.sub_balance(
                self.address(),
                &sponsor_balance,
                &mut substate.to_cleanup_mode(&spec),
            )?;
            state.set_sponsor_for_collateral(
                &contract_address,
                sponsor,
                &(sponsor_balance + prev_sponsor_balance),
            )?;
        }
        Ok(())
    }

    fn add_privilege(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if !state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }

        if input.len() < 64 && input.len() % 32 != 0 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let contract_address = params.sender;
        let location = U256::from(&input[0..32]);
        let expected_length = U256::from(&input[32..64]);
        let actual_length = (input.len() - 64) / 32;
        if location != U256::from(32)
            || U256::from(actual_length) != expected_length
        {
            return Err(vm::Error::InternalContract("invalid length"));
        }

        let mut offset = 64;
        for _ in 0..actual_length {
            let user_addr =
                Address::from_slice(&input[offset + 12..offset + 32]);
            state.add_commission_privilege(
                contract_address,
                params.original_sender,
                user_addr,
            )?;
            offset += 32;
        }
        Ok(())
    }

    fn remove_privilege(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if !state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract(
                "normal account is not allowed to set commission_privilege",
            ));
        }

        if input.len() < 64 && input.len() % 32 != 0 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let contract_address = params.sender;
        let location = U256::from(&input[0..32]);
        let expected_length = U256::from(&input[32..64]);
        let actual_length = (input.len() - 64) / 32;
        if location != U256::from(32)
            || U256::from(actual_length) != expected_length
        {
            return Err(vm::Error::InternalContract("invalid length"));
        }

        let mut offset = 64;
        for _ in 0..actual_length {
            let user_addr =
                Address::from_slice(&input[offset + 12..offset + 32]);
            state.remove_commission_privilege(
                contract_address,
                params.original_sender,
                user_addr,
            )?;
            offset += 32;
        }
        Ok(())
    }
}

impl InternalContractTrait for SponsorWhitelistControl {
    /// Address of the internal contract
    fn address(&self) -> &Address {
        &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS
    }

    /// The gas cost of running this internal contract for the given input data.
    ///
    /// + set_sponsor: SLOAD (current sponsor, balance, (limit)), SSTORE (new
    ///                sponsor, balance, (limit))
    ///   Gas: 10000
    /// + add privilege: SSTORE * list length
    ///   Gas: 5000 * [member list length]
    /// + remove_privilege: SSTORE * list length
    ///   Gas: 5000 * [member list length]
    /// + otherwise
    ///   Gas: 5000
    fn cost(&self, input: Option<&Bytes>) -> U256 {
        if let Some(ref data) = input {
            if data.len() < 4 {
                return U256::from(5000);
            }
            if data[0..4] == [0xe9, 0xac, 0x3d, 0x4a]
                || data[0..4] == [0x08, 0x62, 0xbf, 0x68]
            {
                U256::from(10000)
            } else if data[0..4] == [0xfe, 0x15, 0x15, 0x6c]
                || data[0..4] == [0x44, 0xc0, 0xbd, 0x21]
            {
                if data.len() < 4 + 32 + 32 {
                    U256::from(5000)
                } else {
                    let length = U256::from(&data[36..68]);
                    U256::from(5000) * length
                }
            } else {
                U256::from(5000)
            }
        } else {
            U256::from(5000)
        }
    }

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
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

        if data[0..4] == [0xe9, 0xac, 0x3d, 0x4a] {
            // The first 4 bytes of
            // keccak('set_sponsor_for_gas(address,uint256)')
            // is `0xe9ac3d4a`.
            // 4 bytes `Method ID` + 32 bytes `contract_address` + 32 bytes
            // `upper_bound`.
            self.set_sponsor_for_gas(&data[4..], params, spec, state, substate)
        } else if data[0..4] == [0x08, 0x62, 0xbf, 0x68] {
            // The first 4 bytes of
            // keccak('set_sponsor_for_collateral(address)')
            // is `0x0862bf68`.
            // 4 bytes `Method ID` + 32 bytes `contract_address`.
            self.set_sponsor_for_collateral(
                &data[4..],
                params,
                spec,
                state,
                substate,
            )
        } else if data[0..4] == [0xfe, 0x15, 0x15, 0x6c] {
            // The first 4 bytes of keccak('add_privilege(address[])') is
            // `0xfe15156c`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            self.add_privilege(&data[4..], params, state)
        } else if data[0..4] == [0x44, 0xc0, 0xbd, 0x21] {
            // The first 4 bytes of keccak('remove_privilege(address[])')
            // is `0x44c0bd21`.
            // 4 bytes `Method ID` + 32 bytes location + 32 bytes `length` + ...
            self.remove_privilege(&data[4..], params, state)
        } else {
            Err(vm::Error::InternalContract("unsupported function"))
        }
    }
}
