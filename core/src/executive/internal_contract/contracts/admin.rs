// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::ADMIN_CONTROL_CONTRACT_ADDRESS;

use super::{
    super::impls::admin::*, ExecutionTrait, InterfaceTrait,
    InternalContractTrait, PreExecCheckConfTrait, SolFnTable,
    SolidityFunctionTrait, UpfrontPaymentTrait, SPEC,
};
use crate::{
    evm::{ActionParams, Spec},
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function, rename_interface,
    state::{State, Substate},
    vm,
};
use cfx_types::{Address, U256};

lazy_static! {
    static ref CONTRACT_TABLE: SolFnTable =
        make_function_table!(SetAdminSnake, Destroy);
    static ref CONTRACT_TABLE_V2: SolFnTable =
        make_function_table!(SetAdmin, Destroy, GetAdmin);
}
make_solidity_contract! {
    pub struct AdminControl(ADMIN_CONTROL_CONTRACT_ADDRESS, CONTRACT_TABLE);
}

make_solidity_function! {
    struct SetAdmin((Address, Address), "setAdmin(address,address)");
}
impl_function_type!(SetAdmin, "non_payable_write", gas: SPEC.sstore_reset_gas);

rename_interface! {
    struct SetAdminSnake(SetAdmin, "set_admin(address,address)");
}

impl ExecutionTrait for SetAdmin {
    fn execute_inner(
        &self, inputs: (Address, Address), params: &ActionParams, _spec: &Spec,
        state: &mut State, _substate: &mut Substate,
    ) -> vm::Result<()>
    {
        set_admin(inputs.0, inputs.1, params, state)
    }
}

make_solidity_function! {
    struct Destroy(Address, "destroy(address)");
}
impl_function_type!(Destroy, "non_payable_write", gas: SPEC.sstore_reset_gas);

impl ExecutionTrait for Destroy {
    fn execute_inner(
        &self, input: Address, params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<()>
    {
        destroy(input, params, state, spec, substate)
    }
}

make_solidity_function! {
    struct GetAdmin(Address, "getAdmin(address)", Address);
}
impl_function_type!(GetAdmin, "query_with_default_gas");

impl ExecutionTrait for GetAdmin {
    fn execute_inner(
        &self, input: Address, _: &ActionParams, _: &Spec, state: &mut State,
        _: &mut Substate,
    ) -> vm::Result<Address>
    {
        Ok(state.admin(&input)?)
    }
}

#[test]
fn test_admin_contract_sig() {
    /// The first 4 bytes of keccak('set_admin(address,address)') is 0x73e80cba.
    static SET_ADMIN_SIG: &'static [u8] = &[0x73, 0xe8, 0x0c, 0xba];
    /// The first 4 bytes of keccak('destroy(address)') is 0x00f55d9d.
    static DESTROY_SIG: &'static [u8] = &[0x00, 0xf5, 0x5d, 0x9d];

    assert_eq!(
        SetAdminSnake {}.function_sig().to_vec(),
        SET_ADMIN_SIG.to_vec()
    );
    assert_eq!(Destroy {}.function_sig().to_vec(), DESTROY_SIG.to_vec());
}
