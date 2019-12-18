// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod context;
mod executed;
mod executive;

pub use self::{
    executed::{Executed, ExecutionError, ExecutionResult},
    executive::{
        contract_address, Executive,
        COMMISSION_PRIVILEGE_CONTROL_CONTRACT_ADDRESS, INTERNAL_CONTRACT_CODE,
        INTERNAL_CONTRACT_CODE_HASH, STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    },
};
