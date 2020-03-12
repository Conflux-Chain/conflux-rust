// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    bytes::Bytes,
    state::{State, Substate},
    vm::{self, ActionParams, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("8ad036480160591706c831f0da19d1a424e39469").unwrap();
}

pub struct SponsorWhitelistControl;

impl SponsorWhitelistControl {
    fn set_sponsor(
        &self, input: &[u8], params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if state.is_contract(&params.sender) {
            return Err(vm::Error::InternalContract(
                "contract account is not allowed to sponsor other contract",
            ));
        }

        if input.len() != 64 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let sponsor = params.sender;
        let contract_address = Address::from_slice(&input[12..32]);
        let sponsor_balance = U256::from(&input[32..64]);
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

        if state.balance(&sponsor)? < sponsor_balance {
            return Err(vm::Error::InternalContract(
                "balance is less than sponsor_balance",
            ));
        }

        let prev_sponsor = state.sponsor(&contract_address)?;
        let prev_sponsor_balance = state.sponsor_balance(&contract_address)?;
        let prev_collateral_for_storage =
            state.collateral_for_storage(&contract_address)?;
        let minimum_sponsor_balance_requried = if prev_sponsor != sponsor {
            prev_sponsor_balance + prev_collateral_for_storage
        } else {
            prev_sponsor_balance
        };
        if sponsor_balance < minimum_sponsor_balance_requried {
            return Err(vm::Error::InternalContract(
                "sponsor_balance is not exceed previous sponsor",
            ));
        }

        // If previous sponsor exists, we should refund the `sponsor_balance`,
        // including `collateral_for_storage` if `prev_sponsor != sponsor`.
        if !prev_sponsor.is_zero() {
            state.add_balance(
                &prev_sponsor,
                &minimum_sponsor_balance_requried,
                substate.to_cleanup_mode(&spec),
            )?;
        }
        state.sub_balance(
            &sponsor,
            &sponsor_balance,
            &mut substate.to_cleanup_mode(&spec),
        )?;
        if prev_sponsor == sponsor {
            Ok(state.set_sponsor(
                &contract_address,
                &sponsor,
                &sponsor_balance,
            )?)
        } else {
            // Part of the `sponsor_balance` should be used as
            // `collateral_for_storage`.
            Ok(state.set_sponsor(
                &contract_address,
                &sponsor,
                &(sponsor_balance - prev_collateral_for_storage),
            )?)
        }
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
    fn cost(&self, _input: Option<&Bytes>) -> U256 { U256::zero() }

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
    ) -> vm::Result<()>
    {
        let data = if let Some(ref d) = params.data {
            d as &[u8]
        } else {
            return Err(vm::Error::InternalContract("invalid data"));
        };

        if data.len() < 4 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        if data[0..4] == [0x77, 0x55, 0xfa, 0x12] {
            // The first 4 bytes of keccak('set_sponsor(address,uint256)')
            // is `0x7755fa12`.
            // 4 bytes `Method ID` + 32 bytes `contract_address` + 32 bytes
            // `sponsor_balance`.
            self.set_sponsor(&data[4..], params, spec, state, substate)
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
            Ok(())
        }
    }
}
