// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod context;
mod executed;
mod executive;
#[cfg(test)]
mod executive_tests;
mod internal_contract;
mod vm_exec;

trait CollateralCheckResultToVmResult {
    fn into_vm_result(self) -> Result<(), vmError>;
}

impl CollateralCheckResultToVmResult for CollateralCheckResult {
    fn into_vm_result(self) -> Result<(), vmError> {
        match self {
            CollateralCheckResult::ExceedStorageLimit { .. } => {
                Err(vmError::ExceedStorageLimit)
            }
            CollateralCheckResult::NotEnoughBalance { required, got } => {
                Err(vmError::NotEnoughBalanceForStorage { required, got })
            }
            CollateralCheckResult::Valid => Ok(()),
        }
    }
}

pub use self::{
    context::InternalRefContext,
    executed::*,
    executive::{
        contract_address, Executive, ExecutiveGeneric, ExecutiveResult,
        TransactOptions,
    },
    internal_contract::{
        function, suicide, ABIDecodeError, InternalContractMap,
        InternalContractTrait, SolidityFunctionTrait,
    },
};
use crate::vm::Error as vmError;
use cfx_state::CollateralCheckResult;
