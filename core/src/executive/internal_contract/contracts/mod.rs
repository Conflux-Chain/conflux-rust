// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod sponsor;
mod staking;

mod macros {
    #[cfg(test)]
    pub use crate::check_signature;

    pub use crate::{
        group_impl_is_active, impl_function_type, make_function_table,
        make_solidity_contract, make_solidity_function,
    };

    pub use super::super::{
        activate_at::{BlockNumber, IsActive},
        function::{
            ExecutionTrait, InterfaceTrait, PreExecCheckConfTrait,
            UpfrontPaymentTrait,
        },
        InternalContractTrait, SolidityFunctionTrait,
    };

    pub use crate::spec::CommonParams;
}

pub use self::{
    admin::AdminControl, sponsor::SponsorWhitelistControl, staking::Staking,
};

use super::{
    function::ExecutionTrait, InternalContractTrait, SolidityFunctionTrait,
};
use crate::{evm::Spec, spec::CommonParams};
use cfx_types::Address;
use primitives::BlockNumber;
use std::collections::{BTreeMap, HashMap};

pub(super) type SolFnTable = HashMap<[u8; 4], Box<dyn SolidityFunctionTrait>>;

/// A marco to implement an internal contract.
#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, $gen_table:ident, "active_at_genesis"); ) => {
        $crate::make_solidity_contract! {
            $(#[$attr])* $visibility struct $name ($addr, $gen_table, initialize: |_: &CommonParams| 0u64, is_active: |_: &Spec| true);
        }
    };
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr, $gen_table:ident, initialize: $init:expr, is_active: $is_active:expr); ) => {
        $(#[$attr])*
        $visibility struct $name {
            function_table: SolFnTable
        }

        impl $name {
            pub fn instance() -> Self {
                Self {
                    function_table: $gen_table()
                }
            }
        }

        impl InternalContractTrait for $name {
            fn address(&self) -> &Address { &$addr }
            fn get_func_table(&self) -> &SolFnTable { &self.function_table }
            fn initialize_block(&self, param: &CommonParams) -> BlockNumber{ $init(param) }
        }

        impl IsActive for $name {
            fn is_active(&self, spec: &Spec) -> bool {$is_active(spec)}
        }
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

#[derive(Default)]
pub struct InternalContractMap {
    builtin: BTreeMap<Address, Box<dyn InternalContractTrait>>,
    activation_info: BTreeMap<BlockNumber, Vec<Address>>,
}

impl std::ops::Deref for InternalContractMap {
    type Target = BTreeMap<Address, Box<dyn InternalContractTrait>>;

    fn deref(&self) -> &Self::Target { &self.builtin }
}

impl InternalContractMap {
    pub fn new(params: &CommonParams) -> Self {
        let mut builtin = BTreeMap::new();
        let mut activation_info = BTreeMap::new();
        // We should initialize all the internal contracts here. Even if not all
        // of them are activated at the genesis block. The activation of the
        // internal contracts are controlled by the `CommonParams` and
        // `vm::Spec`.
        let mut internal_contracts = all_internal_contracts();

        while let Some(contract) = internal_contracts.pop() {
            let address = *contract.address();
            let transition_block = contract.initialize_block(params);

            builtin.insert(*contract.address(), contract);
            activation_info
                .entry(transition_block)
                .or_insert(vec![])
                .push(address);
        }

        Self {
            builtin,
            activation_info,
        }
    }

    #[cfg(test)]
    pub fn initialize_for_test() -> Vec<Address> {
        all_internal_contracts()
            .iter()
            .map(|contract| *contract.address())
            .collect()
    }

    pub fn initialized_at_genesis(&self) -> &[Address] {
        self.initialized_at(0)
    }

    pub fn initialized_at(&self, number: BlockNumber) -> &[Address] {
        self.activation_info
            .get(&number)
            .map_or(&[], |vec| vec.as_slice())
    }

    pub fn contract(
        &self, address: &Address, spec: &Spec,
    ) -> Option<&Box<dyn InternalContractTrait>> {
        self.builtin
            .get(address)
            .filter(|&func| func.is_active(spec))
    }
}

/// All Built-in contracts.
pub fn all_internal_contracts() -> Vec<Box<dyn InternalContractTrait>> {
    vec![
        Box::new(AdminControl::instance()),
        Box::new(Staking::instance()),
        Box::new(SponsorWhitelistControl::instance()),
    ]
}
