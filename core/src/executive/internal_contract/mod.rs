// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod contracts;
pub mod function;
mod impls;

pub use self::{contracts::InternalContractMap, impls::suicide};
pub use solidity_abi::ABIDecodeError;

use self::contracts::SolFnTable;
use crate::{
    bytes::Bytes,
    hash::keccak,
    state::CallStackInfo,
    trace::{trace::ExecTrace, Tracer},
    vm::{self, ActionParams, Env, GasLeft, Spec},
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{Address, H256};
use std::{cell::RefCell, sync::Arc};

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
    fn get_func_table(&self) -> SolFnTable;

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, env: &Env, spec: &Spec,
        call_stack: &RefCell<CallStackInfo>, state: &mut dyn StateOpsTrait,
        substate: &mut dyn SubstateTrait,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<GasLeft>
    {
        let call_data = params
            .data
            .as_ref()
            .ok_or(ABIDecodeError("None call data"))?;
        let (fn_sig_slice, call_params) = if call_data.len() < 4 {
            return Err(ABIDecodeError("Incomplete function signature").into());
        } else {
            call_data.split_at(4)
        };

        let mut fn_sig = [0u8; 4];
        fn_sig.clone_from_slice(fn_sig_slice);

        let func_table = self.get_func_table();

        let solidity_fn = func_table
            .get(&fn_sig)
            .ok_or(vm::Error::InternalContract("unsupported function"))?;

        solidity_fn.execute(
            call_params,
            params,
            env,
            spec,
            call_stack,
            state,
            substate,
            tracer,
        )
    }

    fn code(&self) -> Arc<Bytes> { INTERNAL_CONTRACT_CODE.clone() }

    fn code_hash(&self) -> H256 { *INTERNAL_CONTRACT_CODE_HASH }

    fn code_size(&self) -> usize { INTERNAL_CONTRACT_CODE.len() }
}

/// Native implementation of a solidity-interface function.
pub trait SolidityFunctionTrait: Send + Sync {
    // TODO: there are too many parameters here. It should use context instead.
    // However, context can not support all the requirements in internal
    // contracts.
    fn execute(
        &self, input: &[u8], params: &ActionParams, env: &Env, spec: &Spec,
        call_stack: &RefCell<CallStackInfo>, state: &mut dyn StateOpsTrait,
        substate: &mut dyn SubstateTrait,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
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
