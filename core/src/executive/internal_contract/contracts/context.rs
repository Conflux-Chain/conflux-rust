// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{macros::*, ExecutionTrait, SolFnTable};
#[cfg(test)]
use crate::check_signature;
use crate::{
    evm::{ActionParams, GasPriceTier, Spec},
    executive::InternalRefContext,
    impl_function_type, make_function_table, make_solidity_contract,
    make_solidity_function,
    trace::{trace::ExecTrace, Tracer},
    vm,
};
use cfx_parameters::internal_contract_addresses::CONTEXT_ADDRESS;
use cfx_state::state_trait::StateOpsTrait;
use cfx_types::{Address, U256};
#[cfg(test)]
use rustc_hex::FromHex;

make_solidity_contract! {
    pub struct Context(CONTEXT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip64, is_active: |spec: &Spec| spec.cip64);
}

fn generate_fn_table() -> SolFnTable { make_function_table!(EpochNumber) }

group_impl_is_active!(|spec: &Spec| spec.cip64, EpochNumber);

make_solidity_function! {
    struct EpochNumber((), "epochNumber()", U256);
}

// same gas cost as the `NUMBER` opcode
impl_function_type!(EpochNumber, "query", gas: |spec: &Spec| spec.tier_step_gas[(GasPriceTier::Base).idx()]);

impl ExecutionTrait for EpochNumber {
    fn execute_inner(
        &self, _input: (), _params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<U256>
    {
        Ok(U256::from(context.env.epoch_height))
    }
}

#[test]
fn test_context_contract_sig() {
    check_signature!(EpochNumber, "f4145a83");
}
