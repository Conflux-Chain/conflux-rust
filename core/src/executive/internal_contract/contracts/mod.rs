// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod sponsor;
mod staking;

use super::{
    sol_func::{
        ExecutionTrait, InterfaceTrait, PreExecCheckConfTrait,
        UpfrontPaymentTrait,
    },
    InternalContractTrait, SolidityFunctionTrait,
};
use std::collections::HashMap;

pub use self::{
    admin::{AdminControl, ADMIN_CONTROL_CONTRACT_ADDRESS},
    sponsor::{
        SponsorWhitelistControl, SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    },
    staking::{Staking, STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS},
};

use crate::evm::Spec;

lazy_static! {
    static ref SPEC: Spec = Spec::default();
}

pub(super) type SolFnTable = HashMap<[u8; 4], Box<dyn SolidityFunctionTrait>>;

/// Built-in instruction factory.
pub fn internal_contract_factory(name: &str) -> Box<dyn InternalContractTrait> {
    match name {
        "admin" => Box::new(AdminControl) as Box<dyn InternalContractTrait>,
        "staking" => Box::new(Staking) as Box<dyn InternalContractTrait>,
        "sponsor" => {
            Box::new(SponsorWhitelistControl) as Box<dyn InternalContractTrait>
        }
        _ => panic!("invalid internal contract name: {}", name),
    }
}

#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr,$table:expr); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name;

        impl InternalContractTrait for $name {
            /// Address of the internal contract
            fn address(&self) -> &Address { &$addr }

            fn get_func_table(&self) -> &SolFnTable { &$table }
        }
    };
}

#[macro_export]
macro_rules! make_function_table {
    ($($func:ident), *) => { {
                let mut table = SolFnTable::new();
                $( table.insert($func.function_sig(), Box::new($func)); ) *
                table

        }}
}
