// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod activate_at;
mod contracts;
pub mod function;
mod impls;
mod internal_context;

pub use self::{
    contracts::InternalContractMap, impls::suicide,
    internal_context::InternalRefContext,
};
pub use solidity_abi::ABIDecodeError;

use self::{activate_at::IsActive, contracts::SolFnTable};
use crate::{
    bytes::Bytes,
    hash::keccak,
    spec::CommonParams,
    trace::{trace::ExecTrace, Tracer},
    vm::{self, ActionParams, GasLeft},
};
use cfx_types::{Address, H256};
use primitives::BlockNumber;
use solidity_abi::{ABIEncodable, EventIndexEncodable};
use std::sync::Arc;

lazy_static! {
    static ref INTERNAL_CONTRACT_CODE: Arc<Bytes> =
        Arc::new(vec![0u8, 0u8, 0u8, 0u8]);
    static ref INTERNAL_CONTRACT_CODE_HASH: H256 = keccak([0u8, 0u8, 0u8, 0u8]);
}

/// Native implementation of an internal contract.
pub trait InternalContractTrait: Send + Sync + IsActive {
    /// Address of the internal contract
    fn address(&self) -> &Address;

    /// Time point to run `new_contract_with_admin` for such a internal contract
    fn initialize_block(&self, params: &CommonParams) -> BlockNumber;

    /// A hash-map for solidity function sig and execution handler.
    fn get_func_table(&self) -> &SolFnTable;

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, context: &mut InternalRefContext,
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
            .filter(|&func| func.is_active(context.spec))
            .ok_or(vm::Error::InternalContract(
                "unsupported function".into(),
            ))?;

        solidity_fn.execute(call_params, params, context, tracer)
    }

    fn code(&self) -> Arc<Bytes> { INTERNAL_CONTRACT_CODE.clone() }

    fn code_hash(&self) -> H256 { *INTERNAL_CONTRACT_CODE_HASH }

    fn code_size(&self) -> usize { INTERNAL_CONTRACT_CODE.len() }
}

/// Native implementation of a solidity-interface function.
pub trait SolidityFunctionTrait: Send + Sync + IsActive {
    fn execute(
        &self, input: &[u8], params: &ActionParams,
        context: &mut InternalRefContext,
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

/// Native implementation of a solidity-interface function.
pub trait SolidityEventTrait: Send + Sync {
    type IndexedType: EventIndexEncodable;
    type NonIndexedType: ABIEncodable;

    fn log(
        &self, indexed: Self::IndexedType, non_indexed: Self::NonIndexedType,
        param: &ActionParams, context: &mut InternalRefContext,
        _tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> vm::Result<()>
    {
        let mut topics = vec![self.event_sig()];
        topics.extend_from_slice(&indexed.indexed_event_encode());

        let data = non_indexed.abi_encode();

        context.log(param, topics, data)
    }

    /// The string for function sig
    fn name(&self) -> &'static str;

    /// The event signature
    fn event_sig(&self) -> H256 { keccak(self.name()) }
}
