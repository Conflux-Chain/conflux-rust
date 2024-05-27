// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::PARAMS_CONTROL_CONTRACT_ADDRESS;
use cfx_types::{Address, U256};
use solidity_abi_derive::ABIVariable;

use cfx_vm_interpreter::GasPriceTier;

use super::{super::impls::params_control::*, preludes::*};

make_solidity_contract! {
    pub struct ParamsControl(PARAMS_CONTROL_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip94n, is_active: |spec: &Spec| spec.cip94);
}
fn generate_fn_table() -> SolFnTable {
    make_function_table!(
        CastVote,
        ReadVote,
        CurrentRound,
        TotalVotes,
        PosStakeForVotes
    )
}
group_impl_is_active!(
    |spec: &Spec| spec.cip94,
    CastVote,
    ReadVote,
    CurrentRound,
    TotalVotes
);
group_impl_is_active!(|spec: &Spec| spec.cip105, PosStakeForVotes,);

make_solidity_event! {
    pub struct VoteEvent("Vote(uint64,address,uint16,uint256[3])", indexed: (u64,Address,u16), non_indexed: [U256;3]);
}
make_solidity_event! {
    pub struct RevokeEvent("Revoke(uint64,address,uint16,uint256[3])", indexed: (u64,Address,u16), non_indexed: [U256;3]);
}

make_solidity_function! {
    struct CastVote((u64, Vec<Vote>), "castVote(uint64,(uint16,uint256[3])[])");
}
impl_function_type!(CastVote, "non_payable_write");

impl UpfrontPaymentTrait for CastVote {
    fn upfront_gas_payment(
        &self, (_, votes): &(u64, Vec<Vote>), _params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256> {
        let spec = context.spec;
        Ok(cast_vote_gas(votes.len(), spec).into())
    }
}

impl SimpleExecutionTrait for CastVote {
    fn execute_inner(
        &self, inputs: (u64, Vec<Vote>), params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<()> {
        cast_vote(params.sender, inputs.0, inputs.1, params, context)
    }
}

make_solidity_function! {
    struct ReadVote(Address, "readVote(address)", Vec<Vote>);
}

impl_function_type!(ReadVote, "query", gas: |spec: &Spec| params_index_max(spec) * OPTION_INDEX_MAX * (spec.sload_gas + 2 * spec.sha3_gas));

impl SimpleExecutionTrait for ReadVote {
    fn execute_inner(
        &self, input: Address, params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<Vec<Vote>> {
        read_vote(input, params, context)
    }
}

make_solidity_function! {
    struct CurrentRound((), "currentRound()", u64);
}
impl_function_type!(CurrentRound, "query", gas: |spec:&Spec| spec.tier_step_gas[(GasPriceTier::Low).idx()]);
impl SimpleExecutionTrait for CurrentRound {
    fn execute_inner(
        &self, _input: (), _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<u64> {
        Ok(
            (context.env.number - context.spec.cip94_activation_block_number)
                / context.spec.params_dao_vote_period
                + 1,
        )
    }
}

make_solidity_function! {
    struct TotalVotes(u64, "totalVotes(uint64)", Vec<Vote>);
}
impl_function_type!(TotalVotes, "query", gas: |spec: &Spec| params_index_max(spec) * OPTION_INDEX_MAX * spec.sload_gas);

impl SimpleExecutionTrait for TotalVotes {
    fn execute_inner(
        &self, input: u64, _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<Vec<Vote>> {
        total_votes(input, context)
    }
}

make_solidity_function! {
    struct PosStakeForVotes(u64, "posStakeForVotes(uint64)", U256);
}
impl_function_type!(PosStakeForVotes, "query", gas: |spec: &Spec| 2 * spec.sload_gas);

impl SimpleExecutionTrait for PosStakeForVotes {
    fn execute_inner(
        &self, input: u64, _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        pos_stake_for_votes(input, context)
    }
}

#[derive(ABIVariable, Clone, Eq, PartialEq, Default)]
pub struct Vote {
    pub index: u16,
    pub votes: [U256; OPTION_INDEX_MAX],
}

#[test]
fn test_vote_abi_length() {
    use solidity_abi::ABIVariable;
    assert_eq!(Vote::STATIC_LENGTH, Some(32 * (1 + OPTION_INDEX_MAX)));
}

pub const POW_BASE_REWARD_INDEX: u8 = 0;
pub const POS_REWARD_INTEREST_RATE_INDEX: u8 = 1;
pub const STORAGE_POINT_PROP_INDEX: u8 = 2;
pub const BASEFEE_PROP_INDEX: u8 = 3;
pub const PARAMETER_INDEX_MAX: usize = 4;

pub const OPTION_UNCHANGE_INDEX: u8 = 0;
pub const OPTION_INCREASE_INDEX: u8 = 1;
pub const OPTION_DECREASE_INDEX: u8 = 2;
pub const OPTION_INDEX_MAX: usize = 3;
