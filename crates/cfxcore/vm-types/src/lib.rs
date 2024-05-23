// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod action_params;
mod call_create_type;
mod context;
mod env;
mod error;
mod instruction_result;
mod interpreter_info;
mod return_data;
mod spec;

#[cfg(any(test, feature = "testonly_code"))]
pub mod tests;

pub use self::{
    action_params::{ActionParams, ActionValue, ParamsType},
    call_create_type::{CallType, CreateType},
    context::{
        contract_address, BlockHashSource, Context, ContractCreateResult,
        CreateContractAddress, MessageCallResult,
    },
    env::Env,
    error::{
        separate_out_db_error, Error, ExecTrapError, ExecTrapResult, Result,
        TrapError, TrapKind, TrapResult,
    },
    instruction_result::InstructionResult,
    interpreter_info::InterpreterInfo,
    return_data::{GasLeft, ReturnData},
    spec::{CleanDustMode, Spec, WasmCosts},
};

/// Virtual Machine interface
pub trait Exec: Send {
    /// This function should be used to execute transaction.
    /// It returns either an error, a known amount of gas left, or parameters
    /// to be used to compute the final gas left.
    fn exec(
        self: Box<Self>, context: &mut dyn Context,
    ) -> ExecTrapResult<GasLeft>;
}

/// Resume call interface
pub trait ResumeCall: Send {
    /// Resume an execution for call, returns back the Vm interface.
    fn resume_call(self: Box<Self>, result: MessageCallResult)
        -> Box<dyn Exec>;
}

/// Resume create interface
pub trait ResumeCreate: Send {
    /// Resume an execution from create, returns back the Vm interface.
    fn resume_create(
        self: Box<Self>, result: ContractCreateResult,
    ) -> Box<dyn Exec>;
}
