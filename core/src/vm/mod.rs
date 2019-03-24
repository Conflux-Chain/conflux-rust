// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod action_params;
mod call_type;
mod context;
mod env_info;
mod error;
mod return_data;
mod spec;

pub mod tests;

pub use self::{
    action_params::{ActionParams, ActionValue, ParamsType},
    call_type::CallType,
    context::{
        Context, ContractCreateResult, CreateContractAddress, MessageCallResult,
    },
    env_info::EnvInfo,
    error::{Error, ExecTrapResult, Result, TrapError, TrapKind, TrapResult},
    return_data::{GasLeft, ReturnData},
    spec::{CleanDustMode, Spec, WasmCosts},
};

/// Virtual Machine interface
pub trait Exec: Send {
    /// This function should be used to execute transaction.
    /// It returns either an error, a known amount of gas left, or parameters
    /// to be used to compute the final gas left.
    fn exec(self: Box<Self>, context: &mut Context) -> ExecTrapResult<GasLeft>;
}

/// Resume call interface
pub trait ResumeCall: Send {
    /// Resume an execution for call, returns back the Vm interface.
    fn resume_call(self: Box<Self>, result: MessageCallResult) -> Box<Exec>;
}

/// Resume create interface
pub trait ResumeCreate: Send {
    /// Resume an execution from create, returns back the Vm interface.
    fn resume_create(
        self: Box<Self>, result: ContractCreateResult,
    ) -> Box<Exec>;
}
