// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod account_entry;
mod overlay_account;

mod global_stat;
mod state_object;
mod substate;

use cfx_bytes::Bytes;
use cfx_types::{Address, AddressWithSpace};
use primitives::{DepositList, VoteStakeList};
use std::{collections::HashSet, sync::Arc};

pub use overlay_account::COMMISSION_PRIVILEGE_SPECIAL_KEY;
pub use state_object::{
    distribute_pos_interest, initialize_cip107,
    initialize_or_update_dao_voted_params, settle_collateral_for_all,
    update_pos_status, State,
};
pub use substate::{cleanup_mode, CallStackInfo, Substate};

/// Methods that are intentionally kept private because the fields may not have
/// been loaded from db.
trait AccountEntryProtectedMethods {
    fn deposit_list(&self) -> Option<&DepositList>;
    fn vote_stake_list(&self) -> Option<&VoteStakeList>;
    fn code_size(&self) -> Option<usize>;
    fn code(&self) -> Option<Arc<Bytes>>;
    fn code_owner(&self) -> Option<Address>;
}

/// Mode of dealing with null accounts.
#[derive(PartialEq)]
pub enum CleanupMode<'a> {
    /// Create accounts which would be null.
    ForceCreate,
    /// Don't delete null accounts upon touching, but also don't create them.
    NoEmpty,
    /// Mark all touched accounts.
    /// TODO: We have not implemented the correct behavior of TrackTouched for
    /// internal Contracts.
    TrackTouched(&'a mut HashSet<AddressWithSpace>),
}
