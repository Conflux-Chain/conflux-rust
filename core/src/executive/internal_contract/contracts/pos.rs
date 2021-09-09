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
    make_function_table!(
        Register,
        IncreaseStake,
        Retire,
        GetStatus,
        IdentifierToAddress,
        AddressToIdentifier
    )
}
group_impl_is_active!(
    |spec: &Spec| spec.cip72,
    Register,
    IncreaseStake,
    GetStatus,
    Retire,
    IdentifierToAddress,
    AddressToIdentifier
);

make_solidity_event! {
    pub struct RegisterEvent("Register(bytes32,bytes,bytes)", indexed: H256, non_indexed: (Bytes, Bytes));
}

make_solidity_event! {
    pub struct IncreaseStakeEvent("IncreaseStake(bytes32,uint64)", indexed: H256, non_indexed: u64);
}

make_solidity_event! {
    pub struct RetireEvent("Retire(bytes32,uint64)", indexed: H256, non_indexed: u64);
}

make_solidity_function! {
    struct Register((H256, u64, BlsPubKey, VrfPubKey, BlsProof), "register(bytes32,uint64,bytes,bytes,bytes[2])");
}
impl_function_type!(Register, "non_payable_write");
impl UpfrontPaymentTrait for Register {
    fn upfront_gas_payment(
        &self, inputs: &(H256, u64, BlsPubKey, VrfPubKey, BlsProof),
        _params: &ActionParams, context: &InternalRefContext,
    ) -> U256
    {
        let (_identifier, _vote_power, bls_pubkey, vrf_pubkey, _bls_proof) =
            inputs;
        let spec = context.spec;

        let register_log_data_gas =
            (bls_pubkey.len() + vrf_pubkey.len() + 4 * 32) * spec.log_data_gas;
        let register_log_gas =
            register_log_data_gas + spec.log_gas + spec.log_topic_gas;
        let increase_stake_log_gas =
            32 * spec.log_data_gas + spec.log_gas + spec.log_topic_gas;
        let io_gas =
            4 * spec.sstore_reset_gas + 5 * spec.sload_gas + 7 * spec.sha3_gas;
        let pubkey_hash_gas =
            (bls_pubkey.len() + vrf_pubkey.len() + 31) / 32 * spec.sha3_gas;
        let pubkey_verify_gas = 50_000;

        return U256::from(
            io_gas
                + register_log_gas
                + increase_stake_log_gas
                + pubkey_hash_gas
                + pubkey_verify_gas,
        );
    }
}
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
            identifier,
            params.sender,
            vote_power,
            bls_pubkey,
            vrf_pubkey,
            bls_proof,
            params,
            context,
        )
    }
}

make_solidity_function! {
    struct IncreaseStake(u64, "increaseStake(uint64)");
}
impl_function_type!(IncreaseStake, "non_payable_write");
impl UpfrontPaymentTrait for IncreaseStake {
    fn upfront_gas_payment(
        &self, _: &Self::Input, _params: &ActionParams,
        context: &InternalRefContext,
    ) -> U256
    {
        let spec = context.spec;
        let log_gas =
            32 * spec.log_data_gas + spec.log_gas + spec.log_topic_gas;
        let io_gas =
            2 * spec.sstore_reset_gas + 3 * spec.sload_gas + 3 * spec.sha3_gas;

        return U256::from(log_gas + io_gas);
    }
}
impl ExecutionTrait for IncreaseStake {
    fn execute_inner(
        &self, inputs: u64, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        increase_stake(params.sender, inputs, params, context)
    }
}

make_solidity_function! {
    struct Retire(u64, "retire(uint64)");
}
impl_function_type!(Retire, "non_payable_write", gas: |spec: &Spec| spec.retire_gas);
impl ExecutionTrait for Retire {
    fn execute_inner(
        &self, votes: u64, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        retire(params.sender, votes, params, context)
    }
}

make_solidity_function! {
    struct GetStatus(H256, "getVotes(bytes32)", (u64,u64));
}
impl_function_type!(GetStatus, "query", gas: |spec: &Spec| spec.sload_gas + spec.sha3_gas);
impl ExecutionTrait for GetStatus {
    fn execute_inner(
        &self, inputs: H256, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<(u64, u64)>
    {
        let status = get_status(inputs, params, context)?;
        Ok((status.registered, status.unlocked))
    }
}

make_solidity_function! {
    struct IdentifierToAddress(H256, "identifierToAddress(bytes32)", Address);
}
impl_function_type!(IdentifierToAddress, "query", gas: |spec: &Spec| spec.sload_gas + spec.sha3_gas);
impl ExecutionTrait for IdentifierToAddress {
    fn execute_inner(
        &self, inputs: H256, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<Address>
    {
        identifier_to_address(inputs, params, context)
    }
}

make_solidity_function! {
    struct AddressToIdentifier(Address, "addressToIdentifier(address)", H256);
}
impl_function_type!(AddressToIdentifier, "query", gas: |spec: &Spec| spec.sload_gas + spec.sha3_gas);
impl ExecutionTrait for AddressToIdentifier {
    fn execute_inner(
        &self, inputs: Address, params: &ActionParams,
        context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<H256>
    {
        address_to_identifier(inputs, params, context)
    }
}
