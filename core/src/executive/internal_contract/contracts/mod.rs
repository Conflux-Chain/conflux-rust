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
use cfx_storage::StorageStateTrait;

use crate::evm::Spec;
use cfx_types::Address;
use std::sync::Arc;

lazy_static! {
    static ref SPEC: Spec = Spec::default();
}

pub(super) type SolFnTable<S> =
    HashMap<[u8; 4], Box<dyn SolidityFunctionTrait<S>>>;

/// A marco to implement an internal contract.
#[macro_export]
macro_rules! make_solidity_contract {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($addr:expr,$gen_table:ident); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name<S> {
            phantom: std::marker::PhantomData<S>,
        }

        impl<S> $name<S> {
            pub fn instance() -> Self {
                Self {
                    phantom: Default::default(),
                }
            }
        }

        impl<S: cfx_storage::StorageStateTrait + Send + Sync + 'static> InternalContractTrait<S> for $name<S> {
            fn address(&self) -> &Address { &$addr }
            fn get_func_table(&self) -> SolFnTable<S> { $gen_table::<S>() }
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
        let f = <$interface<cfx_storage::StorageState>>::instance();
        assert_eq!(
            f.function_sig().to_vec(),
            $signature.from_hex().unwrap(),
            "Test solidity signature for {}",
            f.name()
        );
    };
}

pub struct InternalContractMap<S: StorageStateTrait> {
    builtin: Arc<BTreeMap<Address, Box<dyn InternalContractTrait<S>>>>,
}

impl<S: StorageStateTrait> std::ops::Deref for InternalContractMap<S> {
    type Target = Arc<BTreeMap<Address, Box<dyn InternalContractTrait<S>>>>;

    fn deref(&self) -> &Self::Target { &self.builtin }
}

impl<S: StorageStateTrait + Send + Sync + 'static> InternalContractMap<S> {
    pub fn new() -> Self {
        let mut builtin = BTreeMap::new();
        let admin = internal_contract_factory::<S>("admin");
        let sponsor = internal_contract_factory::<S>("sponsor");
        let staking = internal_contract_factory::<S>("staking");
        builtin.insert(*admin.address(), admin);
        builtin.insert(*sponsor.address(), sponsor);
        builtin.insert(*staking.address(), staking);
        Self {
            builtin: Arc::new(builtin),
        }
    }

    pub fn contract(
        &self, address: &Address,
    ) -> Option<&Box<dyn InternalContractTrait<S>>> {
        self.builtin.get(address)
    }
}

/// Built-in instruction factory.
pub fn internal_contract_factory<
    S: StorageStateTrait + Send + Sync + 'static,
>(
    name: &str,
) -> Box<dyn InternalContractTrait<S>> {
    match name {
        "admin" => Box::new(<AdminControl<S>>::instance()),
        "staking" => Box::new(<Staking<S>>::instance()),
        "sponsor" => Box::new(<SponsorWhitelistControl<S>>::instance()),
        _ => panic!("invalid internal contract name: {}", name),
    }
}
