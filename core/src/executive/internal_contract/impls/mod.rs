// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod admin;
mod sponsor;
mod staking;

use super::super::InternalContractTrait;

use self::{
    admin::AdminControl, sponsor::SponsorWhitelistControl, staking::Staking,
};

pub use self::{
    admin::ADMIN_CONTROL_CONTRACT_ADDRESS,
    sponsor::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    staking::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
};

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
