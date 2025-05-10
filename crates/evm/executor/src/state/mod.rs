// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Ledger State: Acts as a caching and checkpoint layer built upon semantically
//! meaningful database interfaces for the execution.

mod checkpoints;

/// Global Statistic Variables: Manages global variables with different
/// checkpoint and caching mechanisms compared to other state variables, such
/// as, `total_issued_tokens`.
mod global_stat;

/// Overlay Account: Defines the access and manipulation object during
/// execution. Each `OverlayAccount` encompasses both the database-stored
/// information of an account and its in-execution data.
mod overlay_account;

/// State Object: Represents the core object of the state module.
mod state_object;

pub use state_object::{
    distribute_pos_interest, initialize_cip107, initialize_cip137,
    initialize_or_update_dao_voted_params, settle_collateral_for_all,
    update_pos_status, State, StateCommitResult,
    COMMISSION_PRIVILEGE_SPECIAL_KEY,
};
#[cfg(test)]
pub use state_object::{get_state_by_epoch_id, get_state_for_genesis_write};
