// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::InternalContractTrait;
use crate::{
    bytes::Bytes,
    parameters::{consensus_internal::CONFLUX_TOKEN, staking::*},
    state::{State, Substate},
    vm::{self, ActionParams, Spec},
};
use cfx_types::{Address, U256};
use std::str::FromStr;

lazy_static! {
    pub static ref ADMIN_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("6060de9e1568e69811c4a398f92c3d10949dc891").unwrap();
}

pub struct AdminControl;

impl AdminControl {
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

    fn destroy(
        &self, input: &[u8], params: &ActionParams, state: &mut State,
        spec: &Spec, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        if input.len() != 32 {
            return Err(vm::Error::InternalContract("invali ddata"));
        }

        let contract_address = Address::from_slice(&input[12..32]);
        debug!("contract_address={:?}", contract_address);

        let requester = &params.original_sender;

        if state.admin(&contract_address)? == *requester {
            let balance = state.balance(&contract_address)?;
            let code_size = state
                .code_size(&contract_address)?
                .expect("code size exists");
            let code_owner = state
                .code_owner(&contract_address)?
                .expect("code owner exists");
            let collateral_for_code = U256::from(code_size)
                * U256::from(CONFLUX_TOKEN)
                / U256::from(NUM_BYTES_PER_CONFLUX_TOKEN);
            state.sub_collateral_for_storage(
                &code_owner,
                &collateral_for_code,
            )?;
            assert_ne!(requester, &contract_address);
            trace!(target: "context", "Destroying {} -> {} (xfer: {})", contract_address, requester, balance);
            state.transfer_balance(
                &contract_address,
                requester,
                &balance,
                substate.to_cleanup_mode(spec),
            )?;
            substate.suicides.insert(contract_address);
        }

        Ok(())
    }
}

impl InternalContractTrait for AdminControl {
    /// Address of the internal contract
    fn address(&self) -> &Address { &ADMIN_CONTROL_CONTRACT_ADDRESS }

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

        debug!(
            "exec_admin_contrl_contract params={:?} |data|={:?}",
            params,
            data.len()
        );
        debug!(
            "sig: {:?} {:?} {:?} {:?}",
            data[0], data[1], data[2], data[3]
        );
        if data[0..4] == [0x73, 0xe8, 0x0c, 0xba] {
            // The first 4 bytes of keccak('set_admin(address,address)') is
            // 0x73e80cba.
            // 4 bytes `Method ID` + 20 bytes `contract_address` + 20 bytes
            // `new_admin_address`
            self.set_admin(&data[4..], params, state)
        } else if data[0..4] == [0x00, 0xf5, 0x5d, 0x9d] {
            // The first 4 bytes of keccak('destroy(address)') is
            // 0x00f55d9d.
            // 4 bytes 'Method ID` + 20 bytes `contract_address`
            self.destroy(&data[4..], params, state, spec, substate)
        } else {
            Ok(())
        }
    }
}
