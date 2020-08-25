// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod abi;
mod contracts;
pub mod function;
mod impls;

use crate::{
    bytes::Bytes,
    hash::keccak,
    state::{State, Substate},
    vm::{self, ActionParams, GasLeft, Spec},
};
use cfx_types::{Address, H256};
use std::sync::Arc;

use self::contracts::SolFnTable;

pub use self::{
    abi::utils::pull_slice,
    contracts::{
        InternalContractMap, ADMIN_CONTROL_CONTRACT_ADDRESS,
        SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    },
    impls::suicide,
};

pub use self::abi::ABIDecodeError;

lazy_static! {
    static ref INTERNAL_CONTRACT_CODE: Arc<Bytes> =
        Arc::new(vec![0u8, 0u8, 0u8, 0u8]);
    static ref INTERNAL_CONTRACT_CODE_HASH: H256 = keccak([0u8, 0u8, 0u8, 0u8]);
}

/// Native implementation of an internal contract.
pub trait InternalContractTrait: Send + Sync {
    /// Address of the internal contract
    fn address(&self) -> &Address;

    /// A hash-map for solidity function sig and execution handler.
    fn get_func_table(&self) -> &SolFnTable;

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
    ) -> vm::Result<GasLeft>
    {
        let call_data = params
            .data
            .as_ref()
            .ok_or(ABIDecodeError("None call data"))?;
        let mut pointer = call_data.iter();

        let mut fn_sig = [0u8; 4];
        fn_sig.clone_from_slice(pull_slice(&mut pointer, 4)?);
        let input = pointer.as_slice();

        let solidity_fn = self
            .get_func_table()
            .get(&fn_sig)
            .ok_or(vm::Error::InternalContract("unsupported function"))?;

        solidity_fn.execute(input, params, spec, state, substate)
    }

    fn code(&self) -> Arc<Bytes> { INTERNAL_CONTRACT_CODE.clone() }

    fn code_hash(&self) -> H256 { *INTERNAL_CONTRACT_CODE_HASH }

    fn code_size(&self) -> usize { INTERNAL_CONTRACT_CODE.len() }
}

/// Native implementation of a solidity-interface function.
pub trait SolidityFunctionTrait: Send + Sync {
    fn execute(
        &self, input: &[u8], params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<GasLeft>;

    /// The string for function sig
    fn name(&self) -> &'static str;

    /// The function sig for this function
    fn function_sig(&self) -> [u8; 4] {
        let mut answer = [0u8; 4];
        answer.clone_from_slice(&keccak(self.name()).as_ref()[0..4]);
        answer
    }
}
