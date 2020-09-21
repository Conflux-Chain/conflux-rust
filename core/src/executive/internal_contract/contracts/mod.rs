// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod sponsor;
mod staking;

use super::{
    function::{
        ExecutionTrait, InterfaceTrait, PreExecCheckConfTrait,
        UpfrontPaymentTrait,
    },
    InternalContractTrait, SolidityFunctionTrait,
};
use std::collections::{BTreeMap, HashMap};

pub use self::{
    admin::AdminControl, sponsor::SponsorWhitelistControl, staking::Staking,
};

use crate::evm::Spec;
use cfx_types::Address;
use std::sync::Arc;

lazy_static! {
    static ref SPEC: Spec = Spec::default();
}

pub(super) type SolFnTable = HashMap<[u8; 4], Box<dyn SolidityFunctionTrait>>;

/// A marco to implement an internal contract.
#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr,$table:expr); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name;

        impl InternalContractTrait for $name {
            fn address(&self) -> &Address { &$addr }
            fn get_func_table(&self) -> &SolFnTable { &$table }
        }
    };
}

/// A marco to construct the functions table for an internal contract for a list
/// of types implements `SolidityFunctionTrait`.
#[macro_export]
macro_rules! make_function_table {
    ($($func:ident), *) => { {
        let mut table = SolFnTable::new();
        $( table.insert($func.function_sig(), Box::new($func)); ) *
        table
    } }
}

#[macro_export]
macro_rules! rename_interface {
    ( $(#[$attr:meta])* $visibility:vis struct $new_name:ident ($old_name:ident, $interface:expr ); ) => {
        $(#[$attr])* $visibility struct $new_name;

        impl SolidityFunctionTrait for $new_name {
            fn name(&self) -> &'static str { $interface }
            fn execute(
                &self, input: &[u8], params: &ActionParams, spec: &Spec,
                state: &mut State, substate: &mut Substate,
            ) -> vm::Result<vm::GasLeft> {
                $old_name.execute(input, params, spec, state, substate)
            }
        }
     };
}

pub struct InternalContractMap {
    builtin: Arc<BTreeMap<Address, Box<dyn InternalContractTrait>>>,
}

impl std::ops::Deref for InternalContractMap {
    type Target = Arc<BTreeMap<Address, Box<dyn InternalContractTrait>>>;

    fn deref(&self) -> &Self::Target { &self.builtin }
}

impl InternalContractMap {
    pub fn new() -> Self {
        let mut builtin = BTreeMap::new();
        let admin = internal_contract_factory("admin");
        let sponsor = internal_contract_factory("sponsor");
        let staking = internal_contract_factory("staking");
        builtin.insert(*admin.address(), admin);
        builtin.insert(*sponsor.address(), sponsor);
        builtin.insert(*staking.address(), staking);
        Self {
            builtin: Arc::new(builtin),
        }
    }

    pub fn contract(
        &self, address: &Address,
    ) -> Option<&Box<dyn InternalContractTrait>> {
        self.builtin.get(address)
    }
}

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
