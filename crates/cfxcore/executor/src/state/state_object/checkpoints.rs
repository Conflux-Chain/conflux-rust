//! Checkpoints: Defines the account entry type within checkpoint layers and
//! implements checkpoint maintenance logic.

use cfx_types::AddressWithSpace;
use std::collections::{hash_map::Entry::*, HashMap};

use super::{AccountEntry, GlobalStat, OverlayAccount, State};
use crate::{lazy_discarded_vec::{GetInfo, OrInsert, Update}, unwrap_or_return};

/// An account entry in the checkpoint
#[cfg_attr(test, derive(Clone))]
pub(super) enum CheckpointEntry {
    /// The account has not been read or modified from the database.
    Unchanged,
    /// The recorded state of the account at this checkpoint. It may be
    /// modified or unmodified.
    Recorded(AccountEntry),
}
use CheckpointEntry::*;

impl CheckpointEntry {
    fn from_cache(value: Option<AccountEntry>) -> Self {
        match value {
            Some(v) => Recorded(v),
            None => Unchanged,
        }
    }
}

/// Represents a recoverable point within a checkpoint. including
/// and. The addition of account entries to the checkpoint is lazy; they are
/// only added when the account in the cache is modified, at which point the old
/// version is incorporated into the checkpoint. Therefore, if an account does
/// not exist in the checkpoint, it is implied to be the same as in the cache.
/// This struct efficiently manages state changes and ensures data consistency
/// across transactions.
#[cfg_attr(test, derive(Clone))]
pub(super) struct CheckpointLayer {
    /// Checkpoint for global statistic variables.
    global_stat: GlobalStat,
    /// Checkpoint for  modified account entries.
    ///
    /// An account will only be added only if its cache version is modified. If
    /// an account does not exist in the checkpoint, it is implied to be the
    /// same as in the cache.
    entries: HashMap<AddressWithSpace, CheckpointEntry>,
}

impl CheckpointLayer {
    #[cfg(test)]
    pub fn entries(&self) -> &HashMap<AddressWithSpace, CheckpointEntry> {
        &self.entries
    }
}

impl GetInfo<GlobalStat> for CheckpointLayer {
    fn get_additional_info(&self) -> GlobalStat {
        self.global_stat
    }
}

fn revert_account(entry: &mut AccountEntry, state_checkpoint_id: usize) {
    if let AccountEntry::Cached(ref mut overlay_account, _) = entry {
        overlay_account.revert_checkpoints(state_checkpoint_id);
    }
}

impl Update<HashMap<AddressWithSpace, AccountEntry>> for CheckpointLayer {
    fn update(self, cache: &mut HashMap<AddressWithSpace, AccountEntry>, self_id: usize) {
        for (k, v) in self.entries.into_iter() {
            let mut entry_in_cache = if let Occupied(e) =
                cache.entry(k)
            {
                e
            } else {
                // All the entries in checkpoint must be copied from cache by
                // the following function `insert_to_cache` and
                // `clone_to_checkpoint`.
                // A cache entries will never be removed, except it is revert to
                // an `Unchanged` checkpoint. If this exceptional case happens,
                // this entry has never be loaded or written during transaction
                // execution (regardless the reverted operations), and thus
                // cannot have keys in the checkpoint.

                unreachable!(
                    "Cache should always have more keys than checkpoint"
                );
            };
            match v {
                Recorded(entry_in_checkpoint) => {
                    *entry_in_cache.get_mut() = entry_in_checkpoint;
                    revert_account(entry_in_cache.get_mut(), self_id);
                }
                Unchanged => {
                    // If the AccountEntry in cache does not have a dirty bit,
                    // we can keep it in cache to avoid an duplicate db load.
                    if entry_in_cache.get().is_dirty() {
                        entry_in_cache.remove();
                    }
                    else {
                        revert_account(entry_in_cache.get_mut(), self_id);
                    }
                }
            }
        }
    }
}

impl OrInsert<AddressWithSpace, CheckpointEntry> for CheckpointLayer {
    fn entry_or_insert(&mut self, key: AddressWithSpace, value: CheckpointEntry) -> bool {
        self.entries.entry_or_insert(key, value)
    }
}

impl State {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    pub fn checkpoint(&mut self) -> usize {
        self.checkpoints.get_mut().add_element(CheckpointLayer {
            global_stat: self.global_stat,
            entries: HashMap::new(),
        })
    }

    /// Merge last checkpoint with previous.
    pub fn discard_checkpoint(&mut self) {
        let num_checkpoints = unwrap_or_return!(self.checkpoints.get_mut().discard_element(true));
        // if there is no checkpoint in state, the state's checkpoints are cleared directly,
        // thus, the accounts in state's cache should all discard all checkpoints
        if num_checkpoints == 0 {
            let cache = self.cache.get_mut();
            for (_, v) in cache.iter_mut() {
                if let AccountEntry::Cached(ref mut overlay_account, _) = v {
                    overlay_account.clear_checkpoints();
                }
            }
        }
    }

    /// Revert to the last checkpoint and discard it.
    pub fn revert_to_checkpoint(&mut self) {
        let global_stat = 
            unwrap_or_return!(self.checkpoints.get_mut().revert_element(self.cache.get_mut()));
        self.global_stat = global_stat;
    }

    /// Insert a new overlay account to cache and incoroprating the old version
    /// to the checkpoint in needed.
    pub(super) fn insert_to_cache(&mut self, account: OverlayAccount) {
        let address = *account.address();
        let old_account_entry = self
            .cache
            .get_mut()
            .insert(address, AccountEntry::new_dirty(account));

        unwrap_or_return!(self.checkpoints.get_mut().notify_last_element(address, CheckpointEntry::from_cache(old_account_entry)));
    }

    /// The caller has changed (or will change) an account in cache and notify
    /// this function to incoroprates the old version to the checkpoint in
    /// needed.
    pub(super) fn notify_checkpoint(
        &self, address: AddressWithSpace, old_account_entry: &AccountEntry,
    ) -> Option<usize> {
        let mut checkpoints = self.checkpoints.write();

        unwrap_or_return!(checkpoints.notify_last_element(address, Recorded(old_account_entry.clone_cache_entry())))
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}
