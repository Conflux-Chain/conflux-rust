//! Checkpoints: Defines the account entry type within checkpoint layers and
//! implements checkpoint maintenance logic.

use cfx_types::AddressWithSpace;
use std::collections::{hash_map::Entry::*, HashMap};

use super::{AccountEntry, GlobalStat, OverlayAccount, State};
use crate::unwrap_or_return;

/// An account entry in the checkpoint
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

impl State {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    pub fn checkpoint(&mut self) -> usize {
        let checkpoints = self.checkpoints.get_mut();
        let index = checkpoints.len();
        checkpoints.push(CheckpointLayer {
            global_stat: self.global_stat,
            entries: HashMap::new(),
        });
        index
    }

    /// Merge last checkpoint with previous.
    pub fn discard_checkpoint(&mut self) {
        // merge with previous checkpoint
        let mut checkpoint =
            unwrap_or_return!(self.checkpoints.get_mut().pop()).entries;

        let prev =
            &mut unwrap_or_return!(self.checkpoints.get_mut().last_mut())
                .entries;

        if prev.is_empty() {
            *prev = checkpoint;
        } else {
            for (k, v) in checkpoint.drain() {
                prev.entry(k).or_insert(v);
            }
        }
    }

    /// Revert to the last checkpoint and discard it.
    pub fn revert_to_checkpoint(&mut self) {
        let CheckpointLayer {
            entries: mut checkpoint,
            global_stat,
        } = unwrap_or_return!(self.checkpoints.get_mut().pop());

        self.global_stat = global_stat;

        for (k, v) in checkpoint.drain() {
            let mut entry_in_cache = if let Occupied(e) =
                self.cache.get_mut().entry(k)
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
                }
                Unchanged => {
                    // If the AccountEntry in cache does not have a dirty bit,
                    // we can keep it in cache to avoid an duplicate db load.
                    if entry_in_cache.get().is_dirty() {
                        entry_in_cache.remove();
                    }
                }
            }
        }
    }

    /// Insert a new overlay account to cache and incoroprating the old version
    /// to the checkpoint in needed.
    pub(super) fn insert_to_cache(&mut self, account: OverlayAccount) {
        let address = *account.address();
        let old_account_entry = self
            .cache
            .get_mut()
            .insert(address, AccountEntry::new_dirty(account));

        let checkpoint =
            unwrap_or_return!(self.checkpoints.get_mut().last_mut());
        checkpoint
            .entries
            .entry(address)
            .or_insert_with(|| CheckpointEntry::from_cache(old_account_entry));
    }

    /// The caller has changed (or will change) an account in cache and notify
    /// this function to incoroprates the old version to the checkpoint in
    /// needed.
    pub(super) fn notify_checkpoint(
        &self, address: AddressWithSpace, old_account_entry: &AccountEntry,
    ) {
        let mut checkpoints = self.checkpoints.write();
        let checkpoint = unwrap_or_return!(checkpoints.last_mut());

        checkpoint
            .entries
            .entry(address)
            .or_insert_with(|| Recorded(old_account_entry.clone_cache_entry()));
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}
