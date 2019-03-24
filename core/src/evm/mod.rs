// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod evm;
#[macro_use]
pub mod factory;
mod instructions;
mod interpreter;
mod vmtype;

#[cfg(test)]
mod tests;

pub use self::{
    evm::{CostType, FinalizationResult, Finalize},
    factory::Factory,
    vmtype::VMType,
};
pub use crate::vm::{
    ActionParams, CallType, CleanDustMode, Context, ContractCreateResult,
    CreateContractAddress, EnvInfo, GasLeft, MessageCallResult, ReturnData,
    Spec,
};
