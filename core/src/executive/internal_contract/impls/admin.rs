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
}

impl InternalContractTrait for AdminControl {
    /// Address of the internal contract
    fn address(&self) -> &Address { &ADMIN_CONTROL_CONTRACT_ADDRESS }

    /// The gas cost of running this internal contract for the given input data.
    fn cost(&self, _input: Option<&Bytes>) -> U256 { U256::zero() }

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, _spec: &Spec, state: &mut State,
        _substate: &mut Substate,
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
            // The first 4 bytes of keccak('set_admin(address,address') is
            // 0x73e80cba 4 bytes `Method ID` + 20 bytes
            // `contract_address` + 20 bytes `new_admin_address`
            self.set_admin(&data[4..], params, state)
        } else {
            Ok(())
        }
    }
}
