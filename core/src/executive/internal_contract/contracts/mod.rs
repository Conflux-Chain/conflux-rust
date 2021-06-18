// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod context;
mod sponsor;
mod staking;
mod macros {
    #[cfg(test)]
    pub use crate::check_signature;

    pub use crate::{
        group_impl_activate_at, impl_activate_at, impl_function_type,
        make_function_table, make_solidity_contract, make_solidity_function,
    };

    pub use super::super::{
        activate_at::{ActivateAtTrait, BlockNumber},
        function::{
            ExecutionTrait, InterfaceTrait, PreExecCheckConfTrait,
            UpfrontPaymentTrait,
        },
        InternalContractTrait, SolidityFunctionTrait,
    };
}

pub use self::{
    admin::AdminControl, context::Context, sponsor::SponsorWhitelistControl,
    staking::Staking,
};

use super::{
    function::ExecutionTrait, InternalContractTrait, SolidityFunctionTrait,
};
use crate::evm::Spec;
use cfx_types::Address;
use primitives::BlockNumber;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

pub(super) type SolFnTable = HashMap<[u8; 4], Box<dyn SolidityFunctionTrait>>;

/// A marco to implement an internal contract.
#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, $gen_table:ident, activate_at: $desc:tt); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name {
        }

        impl $name {
            pub fn instance() -> Self {
                Self {}
            }
        }

        impl InternalContractTrait for $name {
            fn address(&self) -> &Address { &$addr }
            fn get_func_table(&self) -> SolFnTable { $gen_table() }
        }

        impl_activate_at!($name, $desc);
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

#[macro_export]
macro_rules! check_signature {
    ($interface:ident, $signature:expr) => {
        let f = $interface::instance();
        assert_eq!(
            f.function_sig().to_vec(),
            $signature.from_hex::<Vec<u8>>().unwrap(),
            "Test solidity signature for {}",
            f.name()
        );
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
        let context = internal_contract_factory("context");

        builtin.insert(*admin.address(), admin);
        builtin.insert(*sponsor.address(), sponsor);
        builtin.insert(*staking.address(), staking);
        builtin.insert(*context.address(), context);

        Self {
            builtin: Arc::new(builtin),
        }
    }

    pub fn contract(
        &self, address: &Address, block_number: BlockNumber, spec: &Spec,
    ) -> Option<&Box<dyn InternalContractTrait>> {
        self.builtin
            .get(address)
            .filter(|&func| func.activate_at(block_number, spec))
    }
}

/// Built-in instruction factory.
pub fn internal_contract_factory(name: &str) -> Box<dyn InternalContractTrait> {
    match name {
        "admin" => Box::new(AdminControl::instance()),
        "staking" => Box::new(Staking::instance()),
        "sponsor" => Box::new(SponsorWhitelistControl::instance()),
        "context" => Box::new(Context::instance()),
        _ => panic!("invalid internal contract name: {}", name),
    }
}
