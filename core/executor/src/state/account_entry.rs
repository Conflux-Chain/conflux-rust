// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::overlay_account::OverlayAccount;

/// In-memory copy of the account data.
#[derive(Debug)]
pub enum AccountEntry {
    /// Represents an account that is confirmed to be absent from the database.
    DbAbsent,
    /// An in-memory cached account paired with a dirty bit to indicate
    /// modifications.
    Cached(OverlayAccount, bool),
}

use AccountEntry::*;

impl AccountEntry {
    pub fn is_dirty(&self) -> bool { matches!(self, Cached(_, true)) }

    pub fn is_db_absent(&self) -> bool { matches!(self, DbAbsent) }

    pub fn account(&self) -> Option<&OverlayAccount> {
        match self {
            DbAbsent => None,
            Cached(acc, _) => Some(acc),
        }
    }

    pub fn account_mut(&mut self) -> Option<&mut OverlayAccount> {
        match self {
            DbAbsent => None,
            Cached(acc, _) => Some(acc),
        }
    }

    pub fn into_account(self) -> Option<OverlayAccount> {
        match self {
            DbAbsent => None,
            Cached(acc, _) => Some(acc),
        }
    }

    /// Clone dirty data into new `AccountEntry`. This includes
    /// basic account data and modified storage keys.
    pub fn clone_cache(&self) -> AccountEntry {
        match self {
            DbAbsent => DbAbsent,
            Cached(acc, dirty_bit) => Cached(acc.clone_dirty(), *dirty_bit),
        }
    }

    pub fn new_dirty(account: OverlayAccount) -> AccountEntry {
        Cached(account, true)
    }

    pub fn new_loaded(account: Option<OverlayAccount>) -> AccountEntry {
        match account {
            Some(acc) => Cached(acc, false),
            None => DbAbsent,
        }
    }
}
