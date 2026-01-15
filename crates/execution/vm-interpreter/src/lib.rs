// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

mod evm;
#[macro_use]
pub mod factory;
pub mod instructions;
mod interpreter;
mod vmtype;

#[cfg(test)]
mod tests;

pub use self::{
    evm::{CostType, FinalizationResult, Finalize},
    factory::Factory,
    instructions::{GasPriceTier, INSTRUCTIONS, INSTRUCTIONS_CANCUN},
    vmtype::VMType,
};
