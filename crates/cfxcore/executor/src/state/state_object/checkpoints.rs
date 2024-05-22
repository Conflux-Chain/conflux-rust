//! Checkpoints: Defines the account entry type within checkpoint layers and
//! implements checkpoint maintenance logic.

use cfx_types::AddressWithSpace;
use std::collections::{hash_map::Entry::*, HashMap};

use super::{AccountEntry, GlobalStat, OverlayAccount, State};
use crate::unwrap_or_return;

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

    // Attention: the complexity of this function is O(|another.entries|),
    // so carefully consider which is self, and which is another.
    pub(super) fn incorporate_entries(&mut self, another: CheckpointLayer) {
        if self.entries.is_empty() {
            self.entries = another.entries;
        } else {
            for (k, v) in another.entries.into_iter() {
                self.entries.entry(k).or_insert(v);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct CheckpointsLazyDiscard {
    checkpoints: Vec<CheckpointLayer>,
    last_undiscard_indices: Vec<usize>,
    num_undiscards: usize
}

impl CheckpointsLazyDiscard {
    // pub fn init() -> Self {
    //     Self {
    //         checkpoints: Vec::new(),
    //         last_undiscard_indices: Vec::new(),
    //         num_undiscards: 0
    //     }
    // }

    pub fn is_empty(&self) -> bool {
        self.num_undiscards == 0
    }

    pub fn add_checkpoint(&mut self, global_stat: GlobalStat) -> usize {
        let current_index = self.last_undiscard_indices.len();
        self.last_undiscard_indices.push(current_index);
        self.checkpoints.push(CheckpointLayer {
            global_stat,
            entries: HashMap::new(),
        });
        self.num_undiscards += 1;
        self.num_undiscards - 1
    }

    pub fn discard_checkpoint(&mut self, clear_empty: bool) -> Result<usize, String> {
        let num_checkpoints = self.checkpoints.len();
        if num_checkpoints > 0 {
            let current_discard_index = self.last_undiscard_indices[num_checkpoints - 1];
            if current_discard_index == 0 {
                if clear_empty {
                    self.checkpoints = Vec::new();
                    self.last_undiscard_indices = Vec::new();
                }
                assert_eq!(self.num_undiscards, 1);
            }
            else {
                self.last_undiscard_indices[num_checkpoints - 1] = self.last_undiscard_indices[current_discard_index - 1];
                assert!(self.num_undiscards > 1);
            }
            self.num_undiscards -= 1;
            return Ok(current_discard_index)
        }
        else {
            return Err(format!("In discard_checkpoint(), checkpoints is empty"))
        }
    }

    pub fn revert_checkpoint(&mut self) -> Result<CheckpointLayer, String> {
        let current_discard_index = self.discard_checkpoint(false).map_err(|e| format!("In revert_checkpoint(), {}", e))?;
        assert!(current_discard_index < self.last_undiscard_indices.len());
        self.last_undiscard_indices.truncate(current_discard_index);
        let discard_checkpoints = self.checkpoints.split_off(current_discard_index + 1);
        let mut incorporated_checkpoint = self.checkpoints.pop().unwrap();
        for discard_checkpoint in discard_checkpoints.into_iter() {
            incorporated_checkpoint.incorporate_entries(discard_checkpoint)
        }
        Ok(incorporated_checkpoint)
    }

    pub fn notify_checkpoint(&mut self, address: AddressWithSpace, old_account_entry: &AccountEntry) {
        if self.num_undiscards == 0 {
            assert_eq!(self.checkpoints.len(), 0);
            return ()
        }

        let checkpoint = self.checkpoints.last_mut().unwrap();
        checkpoint
            .entries
            .entry(address)
            .or_insert_with(|| Recorded(old_account_entry.clone_cache_entry()));
    }

    pub fn notify_checkpoint_unknown(&mut self, address: AddressWithSpace, old_account_entry: Option<AccountEntry>) {
        if self.num_undiscards == 0 {
            assert_eq!(self.checkpoints.len(), 0);
            return ()
        }

        let checkpoint = self.checkpoints.last_mut().unwrap();
        checkpoint
            .entries
            .entry(address)
            .or_insert_with(|| CheckpointEntry::from_cache(old_account_entry));
    }


    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.num_undiscards
    }

    /// Get the value of storage at a specific checkpoint.
    #[cfg(test)]
    pub fn checkpoint_storage_at(
        &self, start_checkpoint_index: usize)
    -> Option<Vec<CheckpointLayer>> {
        let mut start_checkpoint_index_lazy = self.last_undiscard_indices.len();
        for _ in (start_checkpoint_index..self.num_undiscards).rev() {
            if start_checkpoint_index_lazy == 0 {
                return None
            }
            start_checkpoint_index_lazy = self.last_undiscard_indices[start_checkpoint_index_lazy - 1];
        }
        Some(self.checkpoints[start_checkpoint_index_lazy..].to_vec())
    }
}

impl State {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    pub fn checkpoint(&mut self) -> usize {
        let checkpoints = self.checkpoints.get_mut();
        checkpoints.add_checkpoint(self.global_stat)
        // let index = checkpoints.len();
        // checkpoints.push(CheckpointLayer {
        //     global_stat: self.global_stat,
        //     entries: HashMap::new(),
        // });
        // index
    }

    /// Merge last checkpoint with previous.
    pub fn discard_checkpoint(&mut self) {
        let checkpoints = self.checkpoints.get_mut();
        checkpoints.discard_checkpoint(true).unwrap();
        // // merge with previous checkpoint
        // let mut checkpoint =
        //     unwrap_or_return!(self.checkpoints.get_mut().pop()).entries;

        // let prev =
        //     &mut unwrap_or_return!(self.checkpoints.get_mut().last_mut())
        //         .entries;

        // if prev.is_empty() {
        //     *prev = checkpoint;
        // } else {
        //     for (k, v) in checkpoint.drain() {
        //         prev.entry(k).or_insert(v);
        //     }
        // }
    }

    /// Revert to the last checkpoint and discard it.
    pub fn revert_to_checkpoint(&mut self) {
        let CheckpointLayer {
            entries: mut checkpoint,
            global_stat,
        // } = unwrap_or_return!(self.checkpoints.get_mut().pop());
        } = self.checkpoints.get_mut().revert_checkpoint().unwrap();

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

        self.checkpoints.get_mut().notify_checkpoint_unknown(address, old_account_entry);
        // let checkpoint =
        //     unwrap_or_return!(self.checkpoints.get_mut().last_mut());
        // checkpoint
        //     .entries
        //     .entry(address)
        //     .or_insert_with(|| CheckpointEntry::from_cache(old_account_entry));
    }

    /// The caller has changed (or will change) an account in cache and notify
    /// this function to incoroprates the old version to the checkpoint in
    /// needed.
    pub(super) fn notify_checkpoint(
        &self, address: AddressWithSpace, old_account_entry: &AccountEntry,
    ) {
        let mut checkpoints = self.checkpoints.write();

        checkpoints.notify_checkpoint(address, old_account_entry);
        // let checkpoint = unwrap_or_return!(checkpoints.last_mut());

        // checkpoint
        //     .entries
        //     .entry(address)
        //     .or_insert_with(|| Recorded(old_account_entry.clone_cache_entry()));
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.checkpoints.get_mut().is_empty());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}
