// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_bytes::Bytes;
use cfx_state::CleanupMode;
use cfx_types::Address;

use primitives::{DepositList, VoteStakeList};

pub use state_object::{
    distribute_pos_interest, initialize_or_update_dao_voted_params,
    settle_collateral_for_all, update_pos_status,
};

use crate::{observer::StateTracer, vm::Spec};

pub use self::{
    account_entry::{OverlayAccount, COMMISSION_PRIVILEGE_SPECIAL_KEY},
    substate::{cleanup_mode, CallStackInfo, Substate},
};

mod account_entry;
#[cfg(test)]
mod account_entry_tests;
pub mod prefetcher;
mod state_object;
mod substate;
mod trace;

mod global_stat;
use global_stat::GlobalStat;

pub use state_object::State;

/// Methods that are intentionally kept private because the fields may not have
/// been loaded from db.
trait AccountEntryProtectedMethods {
    fn deposit_list(&self) -> Option<&DepositList>;
    fn vote_stake_list(&self) -> Option<&VoteStakeList>;
    fn code_size(&self) -> Option<usize>;
    fn code(&self) -> Option<Arc<Bytes>>;
    fn code_owner(&self) -> Option<Address>;
}
