// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_parameters::internal_contract_addresses::PARAMS_CONTROL_CONTRACT_ADDRESS;
use cfx_statedb::params_control_entries::OPTION_INDEX_MAX;
use cfx_types::{Address, U256};
use solidity_abi::{
    ABIDecodable, ABIDecodeError, ABIEncodable, ABIPackedEncodable,
    ABIVariable, LinkedBytes,
};

use super::{super::impls::params_control::*, preludes::*};

make_solidity_contract! {
    pub struct ParamsControl(PARAMS_CONTROL_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip94, is_active: |spec: &Spec| spec.cip94);
}
fn generate_fn_table() -> SolFnTable {
    make_function_table!(CastVote, ReadVote)
}
group_impl_is_active!(|spec: &Spec| spec.cip94, CastVote, ReadVote);

make_solidity_function! {
    struct CastVote((u64, Vec<Vote>), "castVote(uint64,(uint16,uint256[3])[])");
}
// FIXME(lpl): What's the gas cost?
impl_function_type!(CastVote, "non_payable_write", gas: |spec: &Spec| spec.sstore_reset_gas);

impl SimpleExecutionTrait for CastVote {
    fn execute_inner(
        &self, inputs: (u64, Vec<Vote>), params: &ActionParams,
        context: &mut InternalRefContext, _tracer: &mut dyn VmObserve,
    ) -> vm::Result<()>
    {
        cast_vote(params.sender, inputs.0, inputs.1, params, context)
    }
}

make_solidity_function! {
    struct ReadVote(Address, "readVote(address)", Vec<Vote>);
}
// FIXME(lpl): What's the gas cost?
impl_function_type!(ReadVote, "query_with_default_gas");

impl SimpleExecutionTrait for ReadVote {
    fn execute_inner(
        &self, input: Address, params: &ActionParams,
        context: &mut InternalRefContext, _tracer: &mut dyn VmObserve,
    ) -> vm::Result<Vec<Vote>>
    {
        read_vote(input, params, context)
    }
}

pub struct Vote {
    pub index: u16,
    pub votes: [U256; OPTION_INDEX_MAX],
}

// FIXME(lpl): Better ABI Serde for struct.
impl ABIVariable for Vote {
    const BASIC_TYPE: bool = false;
    const STATIC_LENGTH: Option<usize> = Some(32 * (1 + OPTION_INDEX_MAX));

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let (index, votes) = ABIDecodable::abi_decode(data)?;
        Ok(Self { index, votes })
    }

    fn to_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes((self.index, self.votes).abi_encode())
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes((self.index, self.votes).abi_packed_encode())
    }
}
