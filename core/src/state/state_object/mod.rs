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

use self::cache_layer::RequireCache;
use super::{
    account_entry::{AccountEntry, AccountState},
    global_stat::GlobalStat,
    overlay_account::OverlayAccount,
    substate, AccountEntryProtectedMethods,
};
use crate::{executive::internal_contract, vm::Spec};
use cfx_state::tracer::StateTracer;
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric as StateDb};
use cfx_types::AddressWithSpace;
use parking_lot::RwLock;
use primitives::Account;
use std::collections::HashMap;

pub use self::{
    collateral::settle_collateral_for_all,
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
    cache: RwLock<HashMap<AddressWithSpace, AccountEntry>>,
    // TODO: try not to make it special?
    global_stat: GlobalStat,

    // Checkpoint to the changes.
    global_stat_checkpoints: RwLock<Vec<GlobalStat>>,
    checkpoints: RwLock<Vec<HashMap<AddressWithSpace, Option<AccountEntry>>>>,
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
            global_stat_checkpoints: Default::default(),
            checkpoints: Default::default(),
            global_stat: world_stat,
            accounts_to_notify: Default::default(),
        })
    }
}
