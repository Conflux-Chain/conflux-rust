// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod context;
pub(super) mod cross_space;
mod future;
pub(super) mod params_control;
pub(super) mod pos;
mod sponsor;
mod staking;
pub(super) mod system_storage;

mod preludes {
    pub use keccak_hash::keccak;
    #[cfg(test)]
    pub use rustc_hex::FromHex;

    pub use cfx_statedb::Result as DbResult;
    pub use cfx_types::{Address, H256};
    pub use primitives::BlockNumber;
    pub use sha3_macro::keccak;

    #[cfg(test)]
    pub use crate::{check_event_signature, check_func_signature};
    pub use crate::{
        evm::{ActionParams, Spec},
        group_impl_is_active, impl_function_type, make_function_table,
        make_solidity_contract, make_solidity_event, make_solidity_function,
        observer::VmObserve,
        spec::CommonParams,
        vm,
    };

    pub use super::super::components::{
        activation::IsActive,
        context::InternalRefContext,
        contract::{InternalContractTrait, SolFnTable},
        event::SolidityEventTrait,
        function::{
            ExecutionTrait, InterfaceTrait, PreExecCheckConfTrait,
            SimpleExecutionTrait, SolidityFunctionTrait, UpfrontPaymentTrait,
        },
    };
}

/// All Built-in contracts. All these addresses will be initialized as an
/// internal contract in the genesis block of test mode.
pub fn all_internal_contracts() -> Vec<Box<dyn super::InternalContractTrait>> {
    vec![
        Box::new(admin::AdminControl::instance()),
        Box::new(staking::Staking::instance()),
        Box::new(sponsor::SponsorWhitelistControl::instance()),
        Box::new(context::Context::instance()),
        Box::new(pos::PoSRegister::instance()),
        Box::new(cross_space::CrossSpaceCall::instance()),
        Box::new(params_control::ParamsControl::instance()),
        Box::new(system_storage::SystemStorage::instance()),
        Box::new(future::Reserved3::instance()),
        Box::new(future::Reserved8::instance()),
        Box::new(future::Reserved9::instance()),
        Box::new(future::Reserved11::instance()),
    ]
}
