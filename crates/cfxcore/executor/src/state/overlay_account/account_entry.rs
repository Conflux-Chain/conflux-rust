// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::OverlayAccount;

/// Entry object in cache and checkpoint layers, adding additional markers
/// like dirty bits to the `OverlayAccount` structure.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub enum AccountEntry {
    /// Represents an account that is confirmed to be absent from the database.
    DbAbsent,
    /// An in-memory cached account paired with a dirty bit to indicate
    /// modifications.
    Cached(OverlayAccount, bool),
}

use cfx_parameters::genesis::GENESIS_ACCOUNT_ADDRESS;
use cfx_types::AddressWithSpace;
use primitives::Account;
use AccountEntry::*;

impl AccountEntry {
    pub fn new_dirty(account: OverlayAccount) -> AccountEntry {
        Cached(account, true)
    }

    /// Contruct `AccountEntry` from account loaded from statedb.
    pub fn new_loaded(account: Option<Account>) -> AccountEntry {
        match account {
            Some(acc) => Cached(
                OverlayAccount::from_loaded(&acc.address().clone(), acc),
                false,
            ),
            None => DbAbsent,
        }
    }

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

    pub fn dirty_account_mut(&mut self) -> Option<&mut OverlayAccount> {
        match self {
            Cached(acc, true) => Some(acc),
            _ => None,
        }
    }

    pub fn into_to_commit_account(self) -> Option<OverlayAccount> {
        // Due to an existing bug, the genesis account is very special. It is
        // always considered to be committed even if it is not dirty.
        const SPECIAL_ADDRESS: AddressWithSpace = AddressWithSpace {
            address: GENESIS_ACCOUNT_ADDRESS,
            space: cfx_types::Space::Native,
        };

        match self {
            Cached(acc, true) => Some(acc),
            Cached(acc, _) if acc.address == SPECIAL_ADDRESS => Some(acc),
            _ => None,
        }
    }

    pub fn clone_cache_entry_for_checkpoint(
        &self, checkpoint_id: usize,
    ) -> AccountEntry {
        match self {
            DbAbsent => DbAbsent,
            Cached(acc, dirty_bit) => Cached(
                acc.clone_account_for_checkpoint(checkpoint_id),
                *dirty_bit,
            ),
        }
    }

    pub fn clone_account(&self) -> AccountEntry {
        match self {
            DbAbsent => DbAbsent,
            Cached(acc, dirty_bit) => Cached(acc.clone_account(), *dirty_bit),
        }
    }
}
