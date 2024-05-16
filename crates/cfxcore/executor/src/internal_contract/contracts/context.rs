// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::CONTEXT_CONTRACT_ADDRESS;
use cfx_types::{Address, BigEndianHash, U256};
use cfx_vm_interpreter::GasPriceTier;

use crate::{internal_contract::epoch_hash_slot, return_if};

use super::preludes::*;

make_solidity_contract! {
    pub struct Context(CONTEXT_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip64, is_active: |spec: &Spec| spec.cip64);
}

fn generate_fn_table() -> SolFnTable {
    make_function_table!(EpochNumber, PoSHeight, FinalizedEpoch, EpochHash)
}

group_impl_is_active!(
    |spec: &Spec| spec.cip64,
    EpochNumber,
    PoSHeight,
    FinalizedEpoch
);

group_impl_is_active!(|spec: &Spec| spec.cip133_core, EpochHash);

make_solidity_function! {
    struct EpochNumber((), "epochNumber()", U256);
}

// same gas cost as the `NUMBER` opcode
impl_function_type!(EpochNumber, "query", gas: |spec: &Spec| spec.tier_step_gas[(GasPriceTier::Base).idx()]);

impl SimpleExecutionTrait for EpochNumber {
    fn execute_inner(
        &self, _input: (), _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        Ok(U256::from(context.env.epoch_height))
    }
}

make_solidity_function! {
    struct PoSHeight((), "posHeight()", U256);
}

// same gas cost as the `NUMBER` opcode
impl_function_type!(PoSHeight, "query", gas: |spec: &Spec| spec.tier_step_gas[(GasPriceTier::Base).idx()]);

impl SimpleExecutionTrait for PoSHeight {
    fn execute_inner(
        &self, _input: (), _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        Ok(context.env.pos_view.unwrap_or(0).into())
    }
}

make_solidity_function! {
    struct FinalizedEpoch((), "finalizedEpochNumber()", U256);
}

// same gas cost as the `NUMBER` opcode
impl_function_type!(FinalizedEpoch, "query", gas: |spec: &Spec| spec.tier_step_gas[(GasPriceTier::Base).idx()]);

impl SimpleExecutionTrait for FinalizedEpoch {
    fn execute_inner(
        &self, _input: (), _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        Ok(context.env.finalized_epoch.unwrap_or(0).into())
    }
}

make_solidity_function! {
    struct EpochHash(U256, "epochHash(uint256)", H256);
}

impl_function_type!(EpochHash, "query", gas: |spec: &Spec| spec.sload_gas);

impl SimpleExecutionTrait for EpochHash {
    fn execute_inner(
        &self, number: U256, _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<H256> {
        return_if!(number > U256::from(u64::MAX));

        let number = number.as_u64();

        return_if!(number < context.spec.cip133_e);
        return_if!(number > context.env.epoch_height);
        return_if!(number
            .checked_add(65536)
            .map_or(false, |n| n <= context.env.epoch_height));
        let res = context.state.get_system_storage(&epoch_hash_slot(number))?;
        Ok(BigEndianHash::from_uint(&res))
    }
}

#[test]
fn test_context_contract_sig() {
    check_func_signature!(EpochNumber, "f4145a83");
}
