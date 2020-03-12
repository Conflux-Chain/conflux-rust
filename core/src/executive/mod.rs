// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod context;
mod executed;
mod executive;
mod internal_contract;

#[cfg(test)]
mod executive_tests;

pub use self::{
    executed::{Executed, ExecutionError, ExecutionResult},
    executive::{contract_address, Executive},
    internal_contract::{
        InternalContractMap, InternalContractTrait,
        SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    },
};
