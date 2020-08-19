// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod error;
mod statedb_ext;
pub use self::{
    error::{Error, ErrorKind, Result},
    impls::{StateDb as StateDbGeneric, StateDbGetOriginalMethods},
    statedb_ext::StateDbExt,
};
pub type StateDb = StateDbGeneric<StorageState>;

// Put StateDb in mod to make sure that methods from statedb_ext don't access
// its fields directly.
mod impls {
    type AccessedEntries = BTreeMap<Vec<u8>, EntryValue>;

    // Use generic type for better test-ability.
    pub struct StateDb<Storage: StorageStateTrait> {
        /// Contains the original storage key values for all loaded and
        /// modified key values.
        accessed_entries: RwLock<AccessedEntries>,
        /// The underlying storage, The storage is updated only upon fn
        /// commit().
        storage: Storage,
    }

    // We skip the accessed_entries for getting original value.
    pub trait StateDbGetOriginalMethods {
        fn get_original_raw_with_proof(
            &self, key: StorageKey,
        ) -> Result<(Option<Box<[u8]>>, StateProof)>;

        fn get_original_storage_root(
            &self, address: &Address,
        ) -> Result<Option<StorageRoot>>;

        fn get_original_storage_root_with_proof(
            &self, address: &Address,
        ) -> Result<(Option<StorageRoot>, NodeMerkleProof)>;
    }

    impl<Storage: StorageStateTrait> StateDb<Storage> {
        pub fn new(storage: Storage) -> Self {
            StateDb {
                accessed_entries: Default::default(),
                storage,
            }
        }

        // Used in storage benchmark.
        #[allow(unused)]
        pub fn get_storage_mut(&mut self) -> &mut Storage { &mut self.storage }

        /// Update the accessed_entries while getting the value.
        pub fn get_raw(&self, key: StorageKey) -> Result<Option<Arc<[u8]>>> {
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

        pub fn set_raw(
            &mut self, key: StorageKey, value: Box<[u8]>,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()>
        {
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "set".into(),
                    key: key.to_key_bytes(),
                    maybe_value: Some(value.clone().into()),
                })
            }
            let key_bytes = key.to_key_bytes();
            let mut entry = self.accessed_entries.get_mut().entry(key_bytes);
            let mut value_arc = Some(value.into());
            let was_vacant = if let Occupied(o) = &mut entry {
                // Have to use take because rust compiler can't know the
                // value_arc is consumed only once.
                o.get_mut().current_value = value_arc.take();
                false
            } else {
                true
            };
            if was_vacant {
                let original_key = self.storage.get(key)?;
                entry.or_insert(EntryValue::new_modified(
                    original_key.map(Into::into),
                    value_arc.take(),
                ));
            }

            Ok(())
        }

        pub fn delete(
            &mut self, key: StorageKey,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()>
        {
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "delete".into(),
                    key: key.to_key_bytes(),
                    maybe_value: None,
                })
            }

            let key_bytes = key.to_key_bytes();
            let mut entry = self.accessed_entries.get_mut().entry(key_bytes);
            let was_vacant = if let Occupied(o) = &mut entry {
                o.get_mut().current_value = None;
                false
            } else {
                true
            };
            if was_vacant {
                let r = self.storage.get(key)?.map(Into::into);
                entry.or_insert(EntryValue::new_modified(r, None));
            }

            Ok(())
        }

        pub fn delete_all<AM: access_mode::AccessMode>(
            &mut self, key_prefix: StorageKey,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<Vec<MptKeyValue>>
        {
            let key_bytes = key_prefix.to_key_bytes();
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: if AM::is_read_only() {
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
                    if !AM::is_read_only() {
                        v.current_value = None;
                    }
                }
            }
            // Then, remove all un-modified existing keys.
            let deleted =
                self.storage.delete_all::<access_mode::Read>(key_prefix)?;
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
                        if !AM::is_read_only() {
                            entry.or_insert(EntryValue::new_modified(
                                Some((&**v).into()),
                                None,
                            ));
                        }
                    }
                }
            }

            Ok(deleted_kvs)
        }

        /// Load the storage layout for state commits.
        /// Modification to storage layout is indifferent from modification of
        /// any other key-values. But as required by MPT structure we
        /// must commit storage layout for any storage changes under the
        /// same account. To load the storage layout, we first load from
        /// the local changes (i.e. accessed_entries), then from the
        /// storage if it's untouched.
        fn load_storage_layout(
            storage_layouts_to_commit: &mut HashMap<Vec<u8>, StorageLayout>,
            address: &[u8], storage: &Storage,
            accessed_entries: &AccessedEntries,
        ) -> Result<()>
        {
            if !storage_layouts_to_commit.contains_key(address) {
                let storage_layout_key = StorageKey::StorageRootKey(address);
                let current_storage_layout = match accessed_entries
                    .get(&storage_layout_key.to_key_bytes())
                {
                    Some(entry) => entry.current_value.clone(),
                    None => storage.get(storage_layout_key)?.map(Into::into),
                };
                storage_layouts_to_commit.insert(
                    address.into(),
                    match current_storage_layout {
                        None => bail!(ErrorKind::IncompleteDatabase(
                            Address::from_slice(address)
                        )),
                        Some(raw) => StorageLayout::from_bytes(raw.as_ref())?,
                    },
                );
            }
            Ok(())
        }

        pub fn set_storage_layout(
            &mut self, address: &Address, storage_layout: StorageLayout,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()>
        {
            self.set_raw(
                StorageKey::new_storage_root_key(address),
                storage_layout.to_bytes().into_boxed_slice(),
                debug_record,
            )
        }

        /// storage_layout is special, because it must always present if there
        /// is any storage value changed.
        fn commit_storage_layout(
            &mut self, address: &[u8], layout: &StorageLayout,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<()>
        {
            let key = StorageKey::StorageRootKey(address);
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
            let mut storage_layouts_to_commit = Default::default();
            let accessed_entries = &*self.accessed_entries.get_mut();
            // First of all, apply all changes to the underlying storage.
            for (k, v) in accessed_entries {
                if v.is_modified() {
                    let storage_key = StorageKey::from_key_bytes(k);
                    match &v.current_value {
                        Some(v) => {
                            self.storage.set(storage_key, (&**v).into())?;
                        }
                        None => {
                            self.storage.delete(storage_key)?;
                        }
                    }

                    if let StorageKey::StorageKey { address_bytes, .. } =
                        &storage_key
                    {
                        if v.current_value.is_some() {
                            Self::load_storage_layout(
                                &mut storage_layouts_to_commit,
                                address_bytes,
                                &self.storage,
                                &accessed_entries,
                            )?;
                        }
                    } else if let StorageKey::AccountKey(address_bytes) =
                        &storage_key
                    {
                        // Contract initialization must set StorageLayout.
                        if (address_bytes.is_builtin_address()
                            || address_bytes.is_contract_address())
                            && v.original_value.is_none()
                        {
                            let result = Self::load_storage_layout(
                                &mut storage_layouts_to_commit,
                                address_bytes,
                                &self.storage,
                                &accessed_entries,
                            );
                            if result.is_err() {
                                warn!(
                                    "Contract address {:?} is created without storage_layout. \
                                    It's probably created by a balance transfer.",
                                    Address::from_slice(address_bytes),
                                );
                            }
                        }
                    } else if let StorageKey::CodeKey {
                        address_bytes, ..
                    } = &storage_key
                    {
                        // Contract initialization must set StorageLayout
                        if address_bytes.is_contract_address()
                            && v.original_value.is_none()
                        {
                            // To assert that we have already set StorageLayout.
                            Self::load_storage_layout(
                                &mut storage_layouts_to_commit,
                                address_bytes,
                                &self.storage,
                                &accessed_entries,
                            )?;
                        }
                    }
                }
            }
            // Set storage layout for contracts with storage modification or
            // contracts with storage_layout initialization or modification.
            let mut storage_layouts =
                std::mem::take(&mut storage_layouts_to_commit);
            for (k, v) in &mut storage_layouts {
                self.commit_storage_layout(k, v, debug_record.as_deref_mut())?;
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
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<StateRootWithAuxInfo>
        {
            let result = match self.storage.get_state_root() {
                Ok(r) => r,
                Err(_) => self.compute_state_root(debug_record)?,
            };
            self.storage.commit(epoch_id)?;

            Ok(result)
        }
    }

    impl<Storage: StorageStateTrait> StateDbGetOriginalMethods
        for StateDb<Storage>
    {
        fn get_original_raw_with_proof(
            &self, key: StorageKey,
        ) -> Result<(Option<Box<[u8]>>, StateProof)> {
            let r = Ok(self.storage.get_with_proof(key)?);
            trace!("get_original_raw_with_proof key={:?}, value={:?}", key, r);
            r
        }

        fn get_original_storage_root(
            &self, address: &Address,
        ) -> Result<Option<StorageRoot>> {
            let key = StorageKey::new_storage_root_key(address);

            let (triplet, _) =
                self.storage.get_node_merkle_all_versions::<NoProof>(key)?;

            Ok(StorageRoot::from_node_merkle_triplet(triplet))
        }

        fn get_original_storage_root_with_proof(
            &self, address: &Address,
        ) -> Result<(Option<StorageRoot>, NodeMerkleProof)> {
            let key = StorageKey::new_storage_root_key(address);

            let (triplet, proof) = self
                .storage
                .get_node_merkle_all_versions::<WithProof>(key)?;

            let root = StorageRoot::from_node_merkle_triplet(triplet);
            Ok((root, proof))
        }
    }

    struct EntryValue {
        original_value: Option<Arc<[u8]>>,
        current_value: Option<Arc<[u8]>>,
    }

    impl EntryValue {
        fn new(value: Option<Arc<[u8]>>) -> Self {
            let value_clone = value.clone();
            Self {
                original_value: value,
                current_value: value_clone,
            }
        }

        fn new_modified(
            original_value: Option<Arc<[u8]>>, current_value: Option<Arc<[u8]>>,
        ) -> Self {
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
    use crate::consensus::debug::{ComputeEpochDebugRecord, StateOp};
    use cfx_internal_common::StateRootWithAuxInfo;
    use cfx_storage::{
        state::{NoProof, WithProof},
        utils::{access_mode, to_key_prefix_iter_upper_bound},
        MptKeyValue, NodeMerkleProof, StateProof, StorageStateTrait,
    };
    use cfx_types::{address_util::AddressUtil, Address};
    use hashbrown::HashMap;
    use parking_lot::RwLock;
    use primitives::{EpochId, StorageKey, StorageLayout, StorageRoot};
    use std::{
        collections::{btree_map::Entry::Occupied, BTreeMap},
        ops::Bound::{Excluded, Included, Unbounded},
        sync::Arc,
    };
}

use cfx_storage::StorageState;
