// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod error;
mod statedb_ext;
pub use self::{
    error::{Error, ErrorKind, Result},
    impls::{StateDb, StateDbGetOriginalMethods},
    statedb_ext::StateDbExt,
};

// Put StateDb in mod to make sure that methods from statedb_ext don't access
// its fields directly.
mod impls {
    pub struct StateDb {
        /// Contains the touched StorageLayouts.
        storage_layouts: HashMap<Vec<u8>, StorageLayout>,
        /// Contains the original storage key values for all loaded and
        /// modified key values.
        accessed_entries: RwLock<BTreeMap<Vec<u8>, EntryValue>>,
        /// The underlying storage, The storage is updated only upon fn
        /// commit().
        storage: StorageState,
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

    impl StateDb {
        pub fn new(storage: StorageState) -> Self {
            StateDb {
                storage_layouts: Default::default(),
                accessed_entries: Default::default(),
                storage,
            }
        }

        // Used in storage benchmark.
        #[allow(unused)]
        pub fn get_storage_mut(&mut self) -> &mut StorageState {
            &mut self.storage
        }

        /// Update the accessed_entries while getting the value.
        pub fn get_raw(&self, key: StorageKey) -> Result<Option<Arc<[u8]>>> {
            let key_bytes = key.to_key_bytes();
            let r;
            let accessed_entries_read_guard = self.accessed_entries.read();
            if let Some(v) = accessed_entries_read_guard.get(&key_bytes) {
                r = v.current_value.clone();
            } else {
                drop(accessed_entries_read_guard);
                let mut accessed_entries = self.accessed_entries.write();
                let entry = accessed_entries.entry(key_bytes);
                let was_vacant = if let Occupied(o) = &entry {
                    r = o.get().current_value.clone();
                    false
                } else {
                    r = self.storage.get(key)?.map(Into::into);
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

        pub fn delete_all(
            &mut self, key_prefix: StorageKey,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> Result<Option<Vec<MptKeyValue>>>
        {
            let key_bytes = key_prefix.to_key_bytes();
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "delete_all".into(),
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
            for (_, v) in iter_range {
                v.current_value = None;
            }
            // Then, remove all un-modified existing keys.
            let deleted =
                self.storage.delete_all::<access_mode::Read>(key_prefix)?;
            // We must update the accessed_entries.
            if let Some(deleted_kvs) = &deleted {
                for (k, v) in deleted_kvs {
                    let mut entry = accessed_entries.entry(k.clone());
                    let was_vacant = if let Occupied(o) = &mut entry {
                        o.get_mut().current_value = None;
                        false
                    } else {
                        true
                    };
                    if was_vacant {
                        entry.or_insert(EntryValue::new_modified(
                            Some((&**v).into()),
                            None,
                        ));
                    }
                }
            }

            Ok(deleted)
        }

        fn load_storage_layout(
            storage_layout: &mut HashMap<Vec<u8>, StorageLayout>,
            storage: &StorageState, address: &[u8],
        ) -> Result<()>
        {
            if !storage_layout.contains_key(address) {
                storage_layout.insert(
                    address.into(),
                    match storage.get(StorageKey::StorageRootKey(address))? {
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
        )
        {
            if let Some(record) = debug_record {
                record.state_ops.push(StateOp::StorageLevelOp {
                    op_name: "set_storage_layout".into(),
                    key: address.as_bytes().into(),
                    maybe_value: Some(storage_layout.to_bytes()),
                })
            };
            self.storage_layouts
                .insert(address.as_bytes().into(), storage_layout);
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
            // First of all, apply all changes to the underlying storage.
            for (k, v) in &*self.accessed_entries.get_mut() {
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
                        Self::load_storage_layout(
                            &mut self.storage_layouts,
                            &self.storage,
                            address_bytes,
                        )?;
                    } else if let StorageKey::AccountKey(address_bytes) =
                        &storage_key
                    {
                        // Internal contract initialization must set
                        // StorageLayout.
                        if address_bytes.is_builtin_address()
                            && v.original_value.is_none()
                        {
                            // To assert that we have aleady set StorageLayout.
                            Self::load_storage_layout(
                                &mut self.storage_layouts,
                                &self.storage,
                                address_bytes,
                            )?;
                        }
                    } else if let StorageKey::CodeKey {
                        address_bytes, ..
                    } = &storage_key
                    {
                        // Contract initialization must set StorageLayout
                        if address_bytes.is_contract_address()
                            && v.original_value.is_none()
                        {
                            // To assert that we have aleady set StorageLayout.
                            Self::load_storage_layout(
                                &mut self.storage_layouts,
                                &self.storage,
                                address_bytes,
                            )?;
                        }
                    }
                }
            }
            // Set storage layout for contracts with storage modification or
            // contracts with storage_layout initialization or modification.
            let mut storage_layouts = std::mem::take(&mut self.storage_layouts);
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
            let result = self.compute_state_root(debug_record);
            self.storage.commit(epoch_id)?;

            result
        }
    }

    impl StateDbGetOriginalMethods for StateDb {
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
    use crate::{
        consensus::debug::{ComputeEpochDebugRecord, StateOp},
        storage::{
            state::{NoProof, WithProof},
            utils::{access_mode, to_key_prefix_iter_upper_bound},
            MptKeyValue, NodeMerkleProof, StateProof, StateRootWithAuxInfo,
            StorageState, StorageStateTrait,
        },
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
