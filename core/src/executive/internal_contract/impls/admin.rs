// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    parameters::staking::*,
    state::{CollateralCheckResult, State, Substate},
    vm::{self, ActionParams, CallType, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref ADMIN_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000000").unwrap();
}

/// The first 4 bytes of keccak('set_admin(address,address)') is 0x73e80cba.
static SET_ADMIN_SIG: &'static [u8] = &[0x73, 0xe8, 0x0c, 0xba];
/// The first 4 bytes of keccak('destroy(address)') is 0x00f55d9d.
static DESTROY_SIG: &'static [u8] = &[0x00, 0xf5, 0x5d, 0x9d];

/// The Actual Implementation of `suicide`.
/// The contract which has non zero `collateral_for_storage` cannot suicide,
/// otherwise it will:
///   1. refund collateral for code
///   2. refund sponsor balance
///   3. refund contract balance
///   4. kill the contract
pub fn suicide(
    contract_address: &Address, refund_address: &Address, state: &mut State,
    spec: &Spec, substate: &mut Substate,
) -> vm::Result<()>
{
    state.checkout_ownership_changed(substate)?;
    match state.checkout_collateral_for_storage(contract_address)? {
        CollateralCheckResult::Valid => {}
        CollateralCheckResult::ExceedStorageLimit { .. } => unreachable!(),
        CollateralCheckResult::NotEnoughBalance { required, got } => {
            return Err(vm::Error::NotEnoughBalanceForStorage {
                required,
                got,
            });
        }
    }

    if !state.collateral_for_storage(contract_address)?.is_zero() {
        return Err(vm::Error::InternalContract(
            "contract has nonzero collateral_for_storage",
        ));
    }
    let balance = state.balance(contract_address)?;

    if let Some(code_size) = state.code_size(contract_address)? {
        // Only refund the code collateral when code exists.
        // If a contract suicides during creation, the code will be empty.
        let code_owner = state
            .code_owner(contract_address)?
            .expect("code owner exists");
        let collateral_for_code = U256::from(code_size) * *COLLATERAL_PER_BYTE;
        state.sub_collateral_for_storage(&code_owner, &collateral_for_code)?;
        *substate.storage_released.entry(code_owner).or_insert(0) +=
            code_size as u64;
    }

    let sponsor_for_gas = state.sponsor_for_gas(contract_address)?;
    let sponsor_for_collateral =
        state.sponsor_for_collateral(contract_address)?;
    let sponsor_balance_for_gas =
        state.sponsor_balance_for_gas(contract_address)?;
    let sponsor_balance_for_collateral =
        state.sponsor_balance_for_collateral(contract_address)?;

    if sponsor_for_gas.is_some() {
        state.add_balance(
            sponsor_for_gas.as_ref().unwrap(),
            &sponsor_balance_for_gas,
            substate.to_cleanup_mode(spec),
        )?;
        state.sub_sponsor_balance_for_gas(
            contract_address,
            &sponsor_balance_for_gas,
        )?;
    }
    if sponsor_for_collateral.is_some() {
        state.add_balance(
            sponsor_for_collateral.as_ref().unwrap(),
            &sponsor_balance_for_collateral,
            substate.to_cleanup_mode(spec),
        )?;
        state.sub_sponsor_balance_for_collateral(
            contract_address,
            &sponsor_balance_for_collateral,
        )?;
    }
    if refund_address == contract_address {
        state.sub_balance(
            contract_address,
            &balance,
            &mut substate.to_cleanup_mode(spec),
        )?;
    } else {
        trace!(target: "context", "Destroying {} -> {} (xfer: {})", contract_address, refund_address, balance);
        state.transfer_balance(
            contract_address,
            refund_address,
            &balance,
            substate.to_cleanup_mode(spec),
        )?;
    }
    substate.suicides.insert(*contract_address);

    Ok(())
}

pub struct AdminControl;

impl AdminControl {
    /// Implementation of `set_admin(address,address)`.
    /// The input should consist of 20 bytes `contract_address` + 20 bytes
    /// `new_admin_address`
    fn set_admin(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
    ) -> vm::Result<()> {
        if input.len() != 64 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let contract_address = Address::from_slice(&input[12..32]);
        let new_admin_address = Address::from_slice(&input[44..64]);
        debug!(
            "contract_address={:?} new_admin_address={:?}",
            contract_address, new_admin_address
        );
        Ok(state.set_admin(
            &params.original_sender,
            &contract_address,
            &new_admin_address,
        )?)
    }

    /// Implementation of `destroy(address)`.
    /// The input should consist of 20 bytes `contract_address`
    fn destroy(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
        spec: &Spec, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invalid data"));
        }

        let contract_address = Address::from_slice(&input[12..32]);
        debug!("contract_address={:?}", contract_address);

        let requester = &params.original_sender;
        let admin = state.admin(&contract_address)?;
        if admin == *requester {
            suicide(&contract_address, &admin, state, spec, substate)
        } else {
            Ok(())
        }
    }
}

impl InternalContractTrait for AdminControl {
    /// Address of the internal contract
    fn address(&self) -> &Address { &ADMIN_CONTROL_CONTRACT_ADDRESS }

    /// The gas cost of running this internal contract for the given input data.
    ///
    /// + set_admin: SLOAD (current admin), SSTORE (new admin)
    ///   Gas: 5000
    /// + destroy: SLOAD (current admin), SELFDESTRUCT
    ///   Gas: 5000
    /// + otherwise
    ///   Gas: 5000
    fn cost(&self, _params: &ActionParams, _state: &mut State) -> U256 {
        U256::from(5000)
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

        debug!(
            "exec_admin_contrl_contract params={:?} |data|={:?}",
            params,
            data.len()
        );
        debug!(
            "sig: {:?} {:?} {:?} {:?}",
            data[0], data[1], data[2], data[3]
        );
        if data[0..4] == *SET_ADMIN_SIG {
            self.set_admin(&data[4..], params, state)
        } else if data[0..4] == *DESTROY_SIG {
            self.destroy(&data[4..], params, state, spec, substate)
        } else {
            Err(vm::Error::InternalContract("unsupported function"))
        }
    }
}
