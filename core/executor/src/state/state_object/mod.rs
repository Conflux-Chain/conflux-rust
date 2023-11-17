macro_rules! try_loaded {
    ($expr:expr) => {
        match $expr {
            Err(e) => {
                return Err(e);
            }
            Ok(None) => {
                return Ok(Default::default());
            }
            Ok(Some(v)) => v,
        }
    };
}

macro_rules! noop_if {
    ($expr:expr) => {
        if $expr {
            return Ok(Default::default());
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($option:expr) => {
        match $option {
            Some(val) => val,
            None => return,
        }
    };
    ($option:expr, $ret:expr) => {
        match $option {
            Some(val) => val,
            None => return $ret,
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return_default {
    ($option:expr) => {
        match $option {
            Some(val) => val,
            None => return Default::default(),
        }
    };
}

mod account_controller;
mod basic_fields;
mod cache_layer;
mod checkpoints;
mod collateral;
mod commit;
mod global_statistics;
mod pos;
mod sponsor;
mod staking;
mod storage_entry;
#[cfg(test)]
mod tests;

use self::{cache_layer::RequireCache, checkpoints::CheckpointLayer};
use super::{
    account_entry::AccountEntry, global_stat::GlobalStat,
    overlay_account::OverlayAccount, substate, AccountEntryProtectedMethods,
};
// use crate::internal_contract;
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric as StateDb};
use cfx_types::AddressWithSpace;
use parking_lot::RwLock;
use primitives::Account;
use std::collections::HashMap;

pub use self::{
    collateral::{initialize_cip107, settle_collateral_for_all},
    pos::{distribute_pos_interest, update_pos_status},
    staking::initialize_or_update_dao_voted_params,
};

pub struct State {
    pub(super) db: StateDb,

    // Only created once for txpool notification.
    // Each element is an Ok(Account) for updated account, or
    // Err(AddressWithSpace) for deleted account.
    accounts_to_notify: Vec<Result<Account, AddressWithSpace>>,

    // Contains the changes to the states and some unchanged state entries.
    // Don't remove cache entries outside state commit, unless you are familiar
    // with checkpoint maintenance.
    cache: RwLock<HashMap<AddressWithSpace, AccountEntry>>,
    // TODO: try not to make it special?
    global_stat: GlobalStat,

    checkpoints: RwLock<Vec<CheckpointLayer>>,
}

impl State {
    pub fn new(db: StateDb) -> DbResult<Self> {
        let initialized = db.is_initialized()?;

        let world_stat = if initialized {
            GlobalStat::loaded(&db)?
        } else {
            GlobalStat::assert_non_inited(&db)?;
            GlobalStat::new()
        };

        Ok(State {
            db,
            cache: Default::default(),
            checkpoints: Default::default(),
            global_stat: world_stat,
            accounts_to_notify: Default::default(),
        })
    }
}
