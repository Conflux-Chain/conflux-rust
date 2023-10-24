use cfx_types::AddressWithSpace;

use crate::state::{
    account_entry::AccountEntry, overlay_account::OverlayAccount,
};

use super::{GlobalStat, State};
use std::collections::{hash_map::Entry::*, HashMap};

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

pub(super) struct CheckpointLayer {
    global_stat: GlobalStat,
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
                // the following function insert_to_cache and
                // clone_to_checkpoint.
                // A cache entries will never be removed, except it is revert to
                // an Unchanged checkpoint. If this exceptional case happens,
                // this entry has never be loaded or write during transaction
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

    pub(super) fn clone_to_checkpoint(
        &self, address: AddressWithSpace, account_entry: &AccountEntry,
    ) {
        let mut checkpoints = self.checkpoints.write();
        let checkpoint = unwrap_or_return!(checkpoints.last_mut());

        checkpoint
            .entries
            .entry(address)
            .or_insert_with(|| Recorded(account_entry.clone_cache()));
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}
