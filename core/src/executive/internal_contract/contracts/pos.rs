// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{super::impls::pos::*, macros::*, ExecutionTrait, SolFnTable};
use crate::{
    evm::{ActionParams, Spec},
    executive::InternalRefContext,
    trace::{trace::ExecTrace, Tracer},
    vm,
};
use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
use cfx_state::state_trait::StateOpsTrait;
use cfx_types::{Address, H256, U256};

type Bytes = Vec<u8>;
type BlsPubKey = Bytes;
type VrfPubKey = Bytes;
type BlsProof = [Bytes; 2];

make_solidity_contract! {
    pub struct PoSRegister(POS_REGISTER_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip72b, is_active: |spec: &Spec| spec.cip72);
}
fn generate_fn_table() -> SolFnTable {
    make_function_table!(Register, IncreaseStake, GetStatus)
}
group_impl_is_active!(
    |spec: &Spec| spec.cip72,
    Register,
    IncreaseStake,
    GetStatus
);

make_solidity_function! {
    struct Register((H256, u64, BlsPubKey, VrfPubKey, BlsProof), "register(bytes32,uint64,bytes,bytes,bytes[2])");
}
impl_function_type!(Register, "non_payable_write", gas: |spec: &Spec| spec.sstore_reset_gas);
impl ExecutionTrait for Register {
    fn execute_inner(
        &self, inputs: (H256, u64, BlsPubKey, VrfPubKey, BlsProof),
        params: &ActionParams, context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        let (identifier, vote_power, bls_pubkey, vrf_pubkey, bls_proof) =
            inputs;
        register(
            identifier, vote_power, bls_pubkey, vrf_pubkey, bls_proof, params,
            context,
        )
    }
}

// TODO: Support sigma protocol verification later.
make_solidity_function! {
    struct IncreaseStake((H256, u64), "increaseStake(bytes32,uint64)");
}
impl_function_type!(IncreaseStake, "non_payable_write", gas: |spec: &Spec| spec.sstore_reset_gas);
impl ExecutionTrait for IncreaseStake {
    fn execute_inner(
        &self, inputs: (H256, u64), params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        increase_stake(inputs.0, inputs.1, params, context)
    }
}

make_solidity_function! {
    struct GetStatus(H256, "getVotes(bytes32)", (u64,u64));
}
impl_function_type!(GetStatus, "query_with_default_gas");
impl ExecutionTrait for GetStatus {
    fn execute_inner(
        &self, inputs: H256, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<(u64, u64)>
    {
        get_status(inputs, params, context)
    }
}

// TODO: confiscate
// TODO: Add caller check
