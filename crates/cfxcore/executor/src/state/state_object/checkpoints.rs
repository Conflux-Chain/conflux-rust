//! Checkpoints: Defines the account entry type within checkpoint layers and
//! implements checkpoint maintenance logic.

use cfx_types::AddressWithSpace;
use std::collections::{hash_map::Entry::*, HashMap};

use super::{
    super::checkpoints::CheckpointEntry::{self, Recorded, Unchanged},
    AccountEntry, GlobalStat, OverlayAccount, State,
};
use crate::{state::checkpoints::CheckpointLayerTrait, unwrap_or_return};

pub(super) type AccountCheckpointEntry = CheckpointEntry<AccountEntry>;

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
    entries: HashMap<AddressWithSpace, AccountCheckpointEntry>,
}

impl CheckpointLayerTrait for CheckpointLayer {
    type Key = AddressWithSpace;
    type Value = AccountEntry;

    fn as_hash_map(&self) -> &HashMap<Self::Key, CheckpointEntry<Self::Value>> {
        &self.entries
    }

    fn as_hash_map_mut(
        &mut self,
    ) -> &mut HashMap<Self::Key, CheckpointEntry<Self::Value>> {
        &mut self.entries
    }
}

impl State {
    /// Create a recoverable checkpoint of this state. Return the checkpoint
    /// index. The checkpoint records any old value which is alive at the
    /// creation time of the checkpoint and updated after that and before
    /// the creation of the next checkpoint.
    pub(crate) fn checkpoint(&mut self) -> usize {
        self.checkpoints.get_mut().push_checkpoint(CheckpointLayer {
            global_stat: self.global_stat,
            entries: HashMap::new(),
        })
    }

    /// Merge last checkpoint with previous.
    pub(crate) fn discard_checkpoint(&mut self) {
        let cleared_addresses =
            unwrap_or_return!(self.checkpoints.get_mut().discard_checkpoint());

        // if there is no checkpoint in state, the state's checkpoints are
        // cleared directly, thus, the accounts in state's cache should
        // all discard all checkpoints
        for addr in cleared_addresses {
            if let Some(AccountEntry::Cached(ref mut overlay_account, true)) =
                self.cache.get_mut().get_mut(&addr)
            {
                overlay_account.clear_checkpoint();
            }
        }
    }

    /// Revert to the last checkpoint and discard it.
    pub(crate) fn revert_to_checkpoint(&mut self) {
        for (layer_id, reverted_layer) in
            unwrap_or_return!(self.checkpoints.get_mut().revert_to_checkpoint())
        {
            self.global_stat = reverted_layer.global_stat;
            apply_checkpoint_layer_to_cache(
                reverted_layer.entries,
                self.cache.get_mut(),
                layer_id,
            );
        }
    }

    pub fn no_checkpoint(&self) -> bool { self.checkpoints.read().is_empty() }

    /// Insert a new overlay account to cache and incoroprating the old version
    /// to the checkpoint in needed.
    pub(super) fn insert_to_cache(&mut self, account: OverlayAccount) {
        let address = *account.address();
        let old_account_entry = self
            .cache
            .get_mut()
            .insert(address, AccountEntry::new_dirty(account));

        self.checkpoints
            .get_mut()
            .insert_element(address, move |_| {
                AccountCheckpointEntry::from_cache(old_account_entry)
            });
    }

    /// The caller has changed (or will change) an account in cache and notify
    /// this function to incoroprates the old version to the checkpoint in
    /// needed.
    pub(super) fn copy_cache_entry_to_checkpoint(
        &self, address: AddressWithSpace, entry_in_cache: &mut AccountEntry,
    ) {
        self.checkpoints
            .write()
            .insert_element(address, |checkpoint_id| {
                let mut new_entry_in_cache = entry_in_cache
                    .clone_cache_entry_for_checkpoint(checkpoint_id);

                std::mem::swap(&mut new_entry_in_cache, entry_in_cache);
                // Rename after memswap
                let old_entry_in_cache = new_entry_in_cache;

                Recorded(old_entry_in_cache)
            });
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn clear(&mut self) {
        assert!(self.no_checkpoint());
        self.cache.get_mut().clear();
        self.global_stat = GlobalStat::loaded(&self.db).expect("no db error");
    }
}

fn apply_checkpoint_layer_to_cache(
    entries: HashMap<AddressWithSpace, AccountCheckpointEntry>,
    cache: &mut HashMap<AddressWithSpace, AccountEntry>, checkpoint_id: usize,
) {
    for (k, v) in entries.into_iter() {
        let mut entry_in_cache = if let Occupied(e) = cache.entry(k) {
            e
        } else {
            // All the entries in checkpoint must be copied from cache by the
            // following function `insert_to_cache` and `clone_to_checkpoint`.
            //
            // A cache entries will never be removed, except it is revert to an
            // `Unchanged` checkpoint. If this exceptional case happens, this
            // entry has never be loaded or written during transaction execution
            // (regardless the reverted operations), and thus cannot have keys
            // in the checkpoint.

            unreachable!("Cache should always have more keys than checkpoint");
        };
        match v {
            Recorded(entry_in_checkpoint) => {
                if let Some(acc) = entry_in_cache.get_mut().dirty_account_mut()
                {
                    acc.revert_checkpoint(checkpoint_id);
                }
                *entry_in_cache.get_mut() = entry_in_checkpoint;
            }
            Unchanged => {
                // If the AccountEntry in cache does not have a dirty bit, we
                // can keep it in cache to avoid an duplicate db load.
                if entry_in_cache.get().is_dirty() {
                    entry_in_cache.remove();
                }
            }
        }
    }
}
