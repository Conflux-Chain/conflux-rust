// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_bytes::Bytes;
use cfx_state::CleanupMode;
use cfx_types::Address;
use primitives::{DepositList, VoteStakeList};
use std::sync::Arc;

pub use account_entry::COMMISSION_PRIVILEGE_SPECIAL_KEY;
pub use state_object::{
    distribute_pos_interest, initialize_or_update_dao_voted_params,
    settle_collateral_for_all, update_pos_status, State,
};
pub use substate::{cleanup_mode, CallStackInfo, Substate};

mod account_entry;
#[cfg(test)]
mod account_entry_tests;
mod global_stat;
pub mod prefetcher;
mod state_object;
mod substate;
mod trace;

/// Methods that are intentionally kept private because the fields may not have
/// been loaded from db.
trait AccountEntryProtectedMethods {
    fn deposit_list(&self) -> Option<&DepositList>;
    fn vote_stake_list(&self) -> Option<&VoteStakeList>;
    fn code_size(&self) -> Option<usize>;
    fn code(&self) -> Option<Arc<Bytes>>;
    fn code_owner(&self) -> Option<Address>;
}
