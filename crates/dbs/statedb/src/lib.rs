// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

pub mod global_params;
#[cfg(feature = "testonly_code")]
mod in_memory_storage;
mod statedb_ext;

use cfx_db_errors::statedb as error;

#[cfg(test)]
mod tests;

pub use self::{
    error::{Error, ErrorKind, Result},
    impls::{StateDb as StateDbGeneric, StateDbCheckpointMethods},
    statedb_ext::StateDbExt,
};
pub use cfx_storage::utils::access_mode;
pub type StateDb = StateDbGeneric;

// Put StateDb in mod to make sure that methods from statedb_ext don't access
// its fields directly.
mod impls {
    type Key = Vec<u8>;
    type Value = Option<Arc<[u8]>>;

    // Use BTreeMap so that we can delete ranges efficiently
    // see `delete_all`
    type AccessedEntries = BTreeMap<Key, EntryValue>;

    // A checkpoint contains the previous values for all keys
    // modified or deleted since the last checkpoint.
    type Checkpoint = BTreeMap<Key, Option<Value>>;

    // Use generic type for better test-ability.
    pub struct StateDb {
        /// Contains the original storage key values for all loaded and
        /// modified key values.
        accessed_entries: RwLock<AccessedEntries>,

        /// The underlying storage, The storage is updated only upon fn
        /// commit().
        storage: Box<dyn StorageStateTrait>,

        /// Checkpoints allow callers to revert un-committed changes.
        checkpoints: Vec<Checkpoint>,
    }

    // Note: Not used currently.
    pub trait StateDbCheckpointMethods {
        /// Create a new checkpoint. Returns the index of the checkpoint.
        fn checkpoint(&mut self) -> usize;

        /// Discard checkpoint.
        /// This means giving up the ability to revert to the latest checkpoint.
        /// Older checkpoints remain valid.
        fn discard_checkpoint(&mut self);

        /// Revert to checkpoint.
        /// Revert all values in `accessed_entries` to their value before
        /// creating the latest checkpoint.
        fn revert_to_checkpoint(&mut self);
    }

    impl StateDb {
        pub fn new(storage: Box<dyn StorageStateTrait>) -> Self {
            StateDb {
                accessed_entries: Default::default(),
                storage,
                checkpoints: Default::default(),
            }
        }

        #[cfg(feature = "testonly_code")]
        pub fn new_for_unit_test() -> Self {
            use self::in_memory_storage::InmemoryStorage;

            Self::new(Box::new(InmemoryStorage::default()))
        }

        #[cfg(feature = "testonly_code")]
        pub fn new_for_unit_test_with_epoch(epoch_id: &EpochId) -> Self {
            use self::in_memory_storage::InmemoryStorage;

            Self::new(Box::new(
                InmemoryStorage::from_epoch_id(epoch_id).unwrap(),
            ))
        }

        /// Set `key` to `value` in latest checkpoint if not set previously.
        fn update_checkpoint(&mut self, key: &Key, value: Option<Value>) {
            if let Some(checkpoint) = self.checkpoints.last_mut() {
                // only insert if key not in checkpoint already
                checkpoint.entry(key.clone()).or_insert(value);
            }
        }

        #[cfg(test)]
        pub fn get_from_cache(&self, key: &Vec<u8>) -> Value {
            self.accessed_entries
                .read()
                .get(key)
                .and_then(|v| v.current_value.clone())
        }

        /// Update the accessed_entries while getting the value.
        pub(crate) fn get_raw(
            &self, key: StorageKeyWithSpace,
        ) -> Result<Option<Arc<[u8]>>> {
            let key_bytes = key.to_key_bytes();
            let mut r;
            let accessed_entries_read_guard = self.accessed_entries.read();
            if let Some(v) = accessed_entries_read_guard.get(&key_bytes) {
                r = v.current_value.clone();
            } else {
                drop(accessed_entries_read_guard);
                r = self.storage.get(key)?.map(Into::into);
                let mut accessed_entries = self.accessed_entries.write();
                let entry = accessed_entries.entry(key_bytes);
                let was_vacant = if let Occupied(o) = &entry {
                    r = o.get().current_value.clone();
                    false
                } else {
                    true
                };
                if was_vacant {
                    entry.or_insert(EntryValue::new(r.clone()));
                }
            };
            trace!("get_raw key={:?}, value={:?}", key, r);
            Ok(r)
        }

        #[cfg(feature = "testonly_code")]
        pub fn get_raw_test(
            &self, key: StorageKeyWithSpace,
        ) -> Result<Option<Arc<[u8]>>> {
            self.get_raw(key)
        }

        /// Set the value under `key` to `value` in `accessed_entries`.
        /// This method will read from db if `key` is not present.
        /// This method will also update the latest checkpoint if necessary.
        fn modify_single_value(
            &mut self, key: StorageKeyWithSpace, value: Option<Box<[u8]>>,
        ) -> Result<()> {
            let key_bytes = key.to_key_bytes();
            let mut entry =
                self.accessed_entries.get_mut().entry(key_bytes.clone());
            let value = value.map(Into::into);

            let old_value = match &mut entry {
                Occupied(o) => {
                    // set `current_value` to `value` and keep the old value
                    Some(std::mem::replace(
                        &mut o.get_mut().current_value,
                        value,
                    ))
                }

                // Vacant
                _ => {
                    let original_value = self.storage.get(key)?.map(Into::into);

                    entry.or_insert(EntryValue::new_modified(
                        original_value,
                        value,
                    ));

                    None
                }
            };

            // store old value in latest checkpoint if not stored yet
            self.update_checkpoint(&key_bytes, old_value);

            Ok(())
        }

        pub(crate) fn set_raw(
            &mut self, key: StorageKeyWithSpace, value: Box<[u8]>,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()> {
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "set".into(),
                    key: key.to_key_bytes(),
                    maybe_value: Some(value.clone().into()),
                })
            }

            self.modify_single_value(key, Some(value))
        }

        pub fn delete(
            &mut self, key: StorageKeyWithSpace,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()> {
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "delete".into(),
                    key: key.to_key_bytes(),
                    maybe_value: None,
                })
            }

            self.modify_single_value(key, None)
        }

        pub fn delete_all<AM: access_mode::AccessMode>(
            &mut self, key_prefix: StorageKeyWithSpace,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<Vec<MptKeyValue>> {
            let key_bytes = key_prefix.to_key_bytes();
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: if AM::READ_ONLY {
                        "iterate"
                    } else {
                        "delete_all"
                    }
                    .into(),
                    key: key_bytes.clone(),
                    maybe_value: None,
                })
            }
            let accessed_entries = self.accessed_entries.get_mut();
            // First, all new keys in the subtree shall be deleted.
            let iter_range_upper_bound =
                to_key_prefix_iter_upper_bound(&key_bytes);
            let iter_range = match &iter_range_upper_bound {
                None => accessed_entries
                    .range_mut::<[u8], _>((Included(&*key_bytes), Unbounded)),

                // delete_all will not delete any key which doesn't exist before
                // the operation. Therefore we don't need to
                // check the accessed_entries prior to the
                // operation.
                Some(upper_bound) => accessed_entries.range_mut::<[u8], _>((
                    Included(&*key_bytes),
                    Excluded(&**upper_bound),
                )),
            };
            let mut deleted_kvs = vec![];
            for (k, v) in iter_range {
                if v.current_value != None {
                    deleted_kvs.push((
                        k.clone(),
                        (&**v.current_value.as_ref().unwrap()).into(),
                    ));
                    if !AM::READ_ONLY {
                        v.current_value = None;
                    }
                }
            }
            // Then, remove all un-modified existing keys.
            let deleted = self.storage.read_all(key_prefix)?;
            // We must update the accessed_entries.
            if let Some(storage_deleted) = &deleted {
                for (k, v) in storage_deleted {
                    let entry = accessed_entries.entry(k.clone());
                    let was_vacant = if let Occupied(_) = &entry {
                        // Nothing to do for existing entry, because we have
                        // already scanned through accessed_entries.
                        false
                    } else {
                        true
                    };
                    if was_vacant {
                        deleted_kvs.push((k.clone(), v.clone()));
                        if !AM::READ_ONLY {
                            entry.or_insert(EntryValue::new_modified(
                                Some((&**v).into()),
                                None,
                            ));
                        }
                    }
                }
            }

            // update latest checkpoint if necessary
            if !AM::READ_ONLY {
                for (k, v) in &deleted_kvs {
                    let v: Value = Some(v.clone().into());
                    self.update_checkpoint(k, Some(v));
                }
            }

            Ok(deleted_kvs)
        }

        /// Load the storage layout for state commits.
        /// Modification to storage layout is the same as modification of
        /// any other key-values. But as required by MPT structure we
        /// must commit storage layout for any storage changes under the
        /// same account. To load the storage layout, we first load from
        /// the local changes (i.e. accessed_entries), then from the
        /// storage if it's untouched.
        fn load_storage_layout(
            storage_layouts_to_rewrite: &mut HashMap<
                (Vec<u8>, Space),
                StorageLayout,
            >,
            accept_account_deletion: bool, address: &[u8], space: Space,
            storage: &dyn StorageStateTrait,
            accessed_entries: &AccessedEntries,
        ) -> Result<()> {
            if !storage_layouts_to_rewrite
                .contains_key(&(address.to_vec(), space))
            {
                let storage_layout_key =
                    StorageKey::StorageRootKey(address).with_space(space);
                let current_storage_layout = match accessed_entries
                    .get(&storage_layout_key.to_key_bytes())
                {
                    Some(entry) => match &entry.current_value {
                        // We don't rewrite storage layout for account to
                        // delete.
                        None => {
                            if accept_account_deletion {
                                return Ok(());
                            } else {
                                // This is defensive checking, against certain
                                // cases when we are not deleting the account
                                // for sure.
                                bail!(ErrorKind::IncompleteDatabase(
                                    Address::from_slice(address)
                                ));
                            }
                        }
                        Some(value_ref) => {
                            StorageLayout::from_bytes(&*value_ref)?
                        }
                    },
                    None => match storage.get(storage_layout_key)? {
                        // A new account must set StorageLayout before accessing
                        // the storage.
                        None => bail!(ErrorKind::IncompleteDatabase(
                            Address::from_slice(address)
                        )),
                        Some(raw) => StorageLayout::from_bytes(raw.as_ref())?,
                    },
                };
                storage_layouts_to_rewrite
                    .insert((address.into(), space), current_storage_layout);
            }
            Ok(())
        }

        pub fn set_storage_layout(
            &mut self, address: &AddressWithSpace,
            storage_layout: StorageLayout,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()> {
            self.set_raw(
                StorageKey::new_storage_root_key(&address.address)
                    .with_space(address.space),
                storage_layout.to_bytes().into_boxed_slice(),
                debug_record,
            )
        }

        /// storage_layout is special, because it must always present if there
        /// is any storage value changed.
        fn commit_storage_layout(
            &mut self, address: &[u8], space: Space, layout: &StorageLayout,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()> {
            let key = StorageKey::StorageRootKey(address).with_space(space);
            let value = layout.to_bytes().into_boxed_slice();
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "commit_storage_layout".into(),
                    key: key.to_key_bytes(),
                    maybe_value: Some(value.clone().into()),
                })
            };
            Ok(self.storage.set(key, value)?)
        }

        fn apply_changes_to_storage(
            &mut self, mut debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()> {
            let mut storage_layouts_to_rewrite = Default::default();
            let accessed_entries = &*self.accessed_entries.get_mut();
            // First of all, apply all changes to the underlying storage.
            for (k, v) in accessed_entries {
                if !v.is_modified() {
                    continue;
                }

                let storage_key =
                    StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(k);
                match &v.current_value {
                    Some(v) => {
                        self.storage.set(storage_key, (&**v).into())?;
                    }
                    None => {
                        self.storage.delete(storage_key)?;
                    }
                }

                match &storage_key.key {
                    StorageKey::StorageKey { address_bytes, .. } => {
                        Self::load_storage_layout(
                            &mut storage_layouts_to_rewrite,
                            /* accept_account_deletion = */
                            v.current_value.is_none(),
                            address_bytes,
                            storage_key.space,
                            self.storage.as_ref(),
                            &accessed_entries,
                        )?;
                    }
                    StorageKey::AccountKey(address_bytes)
                        if (address_bytes.is_builtin_address()
                            || address_bytes.is_contract_address()
                            || storage_key.space == Space::Ethereum)
                            && v.original_value.is_none() =>
                    {
                        let result = Self::load_storage_layout(
                            &mut storage_layouts_to_rewrite,
                            /* accept_account_deletion = */ false,
                            address_bytes,
                            storage_key.space,
                            self.storage.as_ref(),
                            &accessed_entries,
                        );
                        if result.is_err() {
                            debug!(
                                "Contract address {:?} (space {:?}) is created without storage_layout. \
                                It's probably created by a balance transfer.",
                                Address::from_slice(address_bytes), storage_key.space
                            );
                        }
                    }
                    StorageKey::CodeKey { address_bytes, .. }
                        if v.original_value.is_none() =>
                    {
                        Self::load_storage_layout(
                            &mut storage_layouts_to_rewrite,
                            /* accept_account_deletion = */ false,
                            address_bytes,
                            storage_key.space,
                            self.storage.as_ref(),
                            &accessed_entries,
                        )?;
                    }
                    _ => {}
                }
            }
            // Set storage layout for contracts with storage modification or
            // contracts with storage_layout initialization or modification.
            for ((k, space), v) in &mut storage_layouts_to_rewrite {
                self.commit_storage_layout(
                    k,
                    *space,
                    v,
                    debug_record.as_deref_mut(),
                )?;
            }
            // Mark all modification applied.
            self.accessed_entries = Default::default();
            Ok(())
        }

        /// This method is only used for genesis block because state root is
        /// required to compute genesis epoch_id. For other blocks there are
        /// deferred execution so the state root computation is merged inside
        /// commit method.
        pub fn compute_state_root(
            &mut self, debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<StateRootWithAuxInfo> {
            self.apply_changes_to_storage(debug_record)?;
            Ok(self.storage.compute_state_root()?)
        }

        pub fn commit(
            &mut self, epoch_id: EpochId,
            mut debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<StateRootWithAuxInfo> {
            self.apply_changes_to_storage(debug_record.as_deref_mut())?;
            if !self.checkpoints.is_empty() {
                panic!("Active checkpoints during state-db commit");
            }

            let result = match self.storage.get_state_root() {
                Ok(r) => r,
                Err(_) => self.compute_state_root(debug_record)?,
            };

            self.storage.commit(epoch_id)?;

            Ok(result)
        }
    }

    impl StateDbCheckpointMethods for StateDb {
        fn checkpoint(&mut self) -> usize {
            trace!("Creating checkpoint #{}", self.checkpoints.len());
            self.checkpoints.push(BTreeMap::new()); // no values are modified yet
            self.checkpoints.len() - 1
        }

        fn discard_checkpoint(&mut self) {
            // checkpoint `n` (to be discarded)
            let latest = match self.checkpoints.pop() {
                Some(checkpoint) => checkpoint,
                None => {
                    // TODO: panic?
                    warn!("Attempt to discard non-existent checkpoint");
                    return;
                }
            };

            trace!("Discarding checkpoint #{}", self.checkpoints.len());

            // checkpoint `n - 1`
            let previous = match self.checkpoints.last_mut() {
                Some(checkpoint) => checkpoint,
                None => return,
            };

            // insert all keys that have been updated in `n` but not in `n - 1`
            if previous.is_empty() {
                *previous = latest;
            } else {
                for (k, v) in latest {
                    previous.entry(k).or_insert(v);
                }
            }
        }

        fn revert_to_checkpoint(&mut self) {
            let checkpoint = match self.checkpoints.pop() {
                Some(checkpoint) => checkpoint,
                None => {
                    // TODO: panic?
                    warn!("Attempt to revert to non-existent checkpoint");
                    return;
                }
            };

            trace!("Reverting to checkpoint #{}", self.checkpoints.len());

            // revert all modified keys to their old version
            for (k, v) in checkpoint {
                let entry = self.accessed_entries.get_mut().entry(k);

                match (entry, v) {
                    // prior to the checkpoint `k` was not present
                    (Occupied(o), None) => {
                        o.remove();
                    }
                    // the value under `k` has been modified after checkpoint
                    (Occupied(mut o), Some(original_value)) => {
                        o.get_mut().current_value = original_value;
                    }
                    (_, _) => {
                        // keys are not removed from `accessed_entries` other
                        // than during revert and commit, so this should not
                        // happen
                        panic!("Enountered non-existent key while reverting to checkpoint");
                    }
                }
            }
        }
    }

    struct EntryValue {
        original_value: Value,
        current_value: Value,
    }

    impl EntryValue {
        fn new(value: Value) -> Self {
            let value_clone = value.clone();
            Self {
                original_value: value,
                current_value: value_clone,
            }
        }

        fn new_modified(original_value: Value, current_value: Value) -> Self {
            Self {
                original_value,
                current_value,
            }
        }

        fn is_modified(&self) -> bool {
            self.original_value.ne(&self.current_value)
        }
    }

    use super::*;
    use cfx_internal_common::{
        debug::{ComputeEpochDebugRecord, StateOp},
        StateRootWithAuxInfo,
    };
    use cfx_storage::{
        utils::{access_mode, to_key_prefix_iter_upper_bound},
        MptKeyValue, StorageStateTrait,
    };
    use cfx_types::{
        address_util::AddressUtil, Address, AddressWithSpace, Space,
    };
    use hashbrown::HashMap;
    use parking_lot::RwLock;
    use primitives::{
        EpochId, SkipInputCheck, StorageKey, StorageKeyWithSpace, StorageLayout,
    };
    use std::{
        collections::{btree_map::Entry::Occupied, BTreeMap},
        ops::Bound::{Excluded, Included, Unbounded},
        sync::Arc,
    };
}
