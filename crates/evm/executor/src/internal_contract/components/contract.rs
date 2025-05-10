// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{collections::HashMap, sync::Arc};

use cfx_bytes::Bytes;
use cfx_types::{Address, H256};
use cfx_vm_types::{self as vm, ActionParams, GasLeft, Spec};
use keccak_hash::keccak;
use primitives::BlockNumber;
use solidity_abi::ABIDecodeError;

use crate::spec::CommonParams;

use super::{
    InternalRefContext, InternalTrapResult, IsActive, SolidityFunctionTrait,
};

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
    ) -> InternalTrapResult<GasLeft> {
        let func_table = self.get_func_table();

        let (solidity_fn, call_params) =
            match load_solidity_fn(&params.data, func_table, context.spec) {
                Ok(res) => res,
                Err(err) => {
                    return InternalTrapResult::Return(Err(err));
                }
            };

        solidity_fn.execute(call_params, params, context)
    }

    fn code(&self) -> Arc<Bytes> { INTERNAL_CONTRACT_CODE.clone() }

    fn code_hash(&self) -> H256 { *INTERNAL_CONTRACT_CODE_HASH }

    fn code_size(&self) -> usize { INTERNAL_CONTRACT_CODE.len() }
}

pub type SolFnTable = HashMap<[u8; 4], Box<dyn SolidityFunctionTrait>>;

fn load_solidity_fn<'a>(
    data: &'a Option<Bytes>, func_table: &'a SolFnTable, spec: &'a Spec,
) -> vm::Result<(&'a Box<dyn SolidityFunctionTrait>, &'a [u8])> {
    let call_data = data.as_ref().ok_or(ABIDecodeError("None call data"))?;
    let (fn_sig_slice, call_params) = if call_data.len() < 4 {
        return Err(ABIDecodeError("Incomplete function signature").into());
    } else {
        call_data.split_at(4)
    };

    let mut fn_sig = [0u8; 4];
    fn_sig.clone_from_slice(fn_sig_slice);

    let solidity_fn = func_table
        .get(&fn_sig)
        .filter(|&func| func.is_active(spec))
        .ok_or(vm::Error::InternalContract("unsupported function".into()))?;
    Ok((solidity_fn, call_params))
}

/// A marco to implement an internal contract.
#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, "placeholder"); ) => {
        $crate::make_solidity_contract! {
            $(#[$attr])* $visibility struct $name ($addr, || Default::default(), initialize: |_: &CommonParams| u64::MAX, is_active: |_: &Spec| false);
        }
    };
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, $gen_table:expr, "active_at_genesis"); ) => {
        $crate::make_solidity_contract! {
            $(#[$attr])* $visibility struct $name ($addr, $gen_table, initialize: |_: &CommonParams| 0u64, is_active: |_: &Spec| true);
        }
    };
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, $gen_table:expr, initialize: $init:expr, is_active: $is_active:expr); ) => {
        $(#[$attr])*
        $visibility struct $name {
            function_table: SolFnTable
        }

        impl $name {
            pub fn instance() -> Self {
                Self {
                    function_table: $gen_table()
                }
            }
        }

        impl InternalContractTrait for $name {
            fn address(&self) -> &Address { &$addr }
            fn get_func_table(&self) -> &SolFnTable { &self.function_table }
            fn initialize_block(&self, param: &CommonParams) -> BlockNumber{ $init(param) }
        }

        impl IsActive for $name {
            fn is_active(&self, spec: &Spec) -> bool {$is_active(spec)}
        }
    };
}

/// A marco to construct the functions table for an internal contract for a list
/// of types implements `SolidityFunctionTrait`.
#[macro_export]
macro_rules! make_function_table {
    ($($func:ty), *) => { {
        let mut table = SolFnTable::new();
        $({ let f = <$func>::instance(); table.insert(f.function_sig(), Box::new(f)); }) *
        table
    } }
}
