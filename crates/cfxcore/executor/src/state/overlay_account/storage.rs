use super::Substate;

#[cfg(test)]
use super::StorageLayout;
use cfx_parameters::{
    internal_contract_addresses::SYSTEM_STORAGE_ADDRESS,
    staking::COLLATERAL_UNITS_PER_STORAGE_KEY,
};
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric};
use cfx_types::{Address, Space, U256};

use primitives::{
    SkipInputCheck, StorageKey, StorageKeyWithSpace, StorageValue,
};
use std::collections::hash_map::Entry::*;

use super::OverlayAccount;

#[cfg(test)]
use super::super::checkpoints::CheckpointEntry;

impl OverlayAccount {
    pub fn set_storage(
        &mut self, key: Vec<u8>, value: U256, old_value: StorageValue,
        owner: Address, substate: &mut Substate,
    ) -> DbResult<()> {
        // Refund the collateral of old value
        if let Some(old_owner) = old_value.owner {
            substate.record_storage_release(
                &old_owner,
                COLLATERAL_UNITS_PER_STORAGE_KEY,
            );
        }

        // Settle the collateral of new value
        let new_owner = if self.should_have_owner(&key) && !value.is_zero() {
            substate.record_storage_occupy(
                &owner,
                COLLATERAL_UNITS_PER_STORAGE_KEY,
            );
            Some(owner)
        } else {
            None
        };

        self.insert_storage_write_cache(
            key,
            StorageValue {
                owner: new_owner,
                value,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn set_storage_simple(&mut self, key: Vec<u8>, value: U256) {
        self.insert_storage_write_cache(
            key,
            StorageValue { owner: None, value },
        );
    }

    pub fn delete_storage_range(
        &mut self, db_deletion_log: impl Iterator<Item = (Vec<u8>, Box<[u8]>)>,
        key_prefix: &[u8], substate: &mut Substate,
    ) -> DbResult<()> {
        assert_eq!(self.address.space, Space::Native);
        let delete_all = key_prefix.is_empty();

        // Its strong count should be 1 and will not cause memory copy,
        // unless in test and gas estimation.
        assert!(self.storage_write_checkpoint.is_none());
        let write_cache = &mut self.storage_write_cache.write();
        // Must have no checkpoint in range deletion
        for (k, v) in write_cache.iter_mut() {
            if k.starts_with(key_prefix) && !v.value.is_zero() {
                if let Some(old_owner) = v.owner {
                    substate.record_storage_release(
                        &old_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                };
                *v = StorageValue::default();
            }
        }

        let read_cache = self.storage_read_cache.read();
        for (key, raw_value) in db_deletion_log
            .into_iter()
            .filter_map(|(k, v)| Some((decode_storage_key(&k)?, v)))
        {
            match write_cache.entry(key.clone()) {
                Vacant(entry) => {
                    // Propogate the db changes to cache
                    // However, if all keys are removed, we don't update
                    // cache since it will be cleared later.
                    if !delete_all {
                        entry.insert(StorageValue::default());
                    }

                    if !delete_all && !read_cache.contains_key(&key) {
                        // Backward compatible with an existing bug
                        // When remove whitelist entries, if the entry does not
                        // appear in the cache, the collateral is not refunded
                        // correctly.
                        continue;
                    }
                }
                Occupied(_) => {
                    // The key has been modified in cache, and the db holds
                    // a deprecated version.
                    // So we do nothing here.
                    continue;
                }
            }
            // Decode owner
            let StorageValue { owner, value } =
                rlp::decode::<StorageValue>(&raw_value)?;
            assert!(!value.is_zero());
            let owner = owner.unwrap_or(self.address.address);
            substate.record_storage_release(
                &owner,
                COLLATERAL_UNITS_PER_STORAGE_KEY,
            );
        }
        std::mem::drop(read_cache);

        if delete_all {
            write_cache.clear();
            self.storage_read_cache.write().clear();
            self.pending_db_clear = true;
        }
        Ok(())
    }

    fn cached_entry_at(&self, key: &[u8]) -> Option<StorageValue> {
        if let Some(entry) = self.storage_write_cache.read().get(key) {
            return Some(*entry);
        }
        if let Some(entry) = self.storage_read_cache.read().get(key) {
            return Some(*entry);
        }
        None
    }

    #[cfg(test)]
    pub fn cached_value_at_cache(&self, key: &[u8]) -> Option<U256> {
        self.cached_entry_at(key).map(|e| e.value)
    }

    #[cfg(test)]
    fn cached_entry_at_checkpoint(
        &self, key: &[u8], state_checkpoint_id: usize,
    ) -> Option<CheckpointEntry<StorageValue>> {
        if self.storage_write_checkpoint.is_none() {
            return None;
        }
        if self
            .storage_write_checkpoint
            .as_ref()
            .unwrap()
            .get_state_cp_id()
            < state_checkpoint_id
        {
            return None;
        }
        self.storage_write_checkpoint.as_ref().unwrap().get(key)
    }

    #[cfg(test)]
    pub fn cached_value_at_checkpoint(
        &self, key: &[u8], state_checkpoint_id: usize,
    ) -> Option<CheckpointEntry<U256>> {
        self.cached_entry_at_checkpoint(key, state_checkpoint_id)
            .map(|e: CheckpointEntry<StorageValue>| match e {
                CheckpointEntry::Unchanged => CheckpointEntry::Unchanged,
                CheckpointEntry::Recorded(sv) => {
                    CheckpointEntry::Recorded(sv.value)
                }
            })
    }

    // If a contract is removed, and then some one transfer balance to it,
    // `storage_at` will return incorrect value. But this case should never
    // happens.
    pub fn storage_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<U256> {
        Ok(self.storage_entry_at(db, key)?.value)
    }

    // If a contract is removed, and then some one transfer balance to it,
    // `storage_at` will return incorrect value. But this case should never
    // happens.
    pub fn storage_entry_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<StorageValue> {
        Ok(if let Some(value) = self.cached_entry_at(key) {
            value
        } else if self.fresh_storage() {
            StorageValue::default()
        } else {
            self.get_and_cache_storage(db, key)?
        })
    }

    pub fn transient_storage_at(&self, key: &[u8]) -> U256 {
        self.transient_storage_cache
            .read()
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    fn get_and_cache_storage(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<StorageValue> {
        let storage_key =
            StorageKey::new_storage_key(&self.address.address, key.as_ref())
                .with_space(self.address.space);
        let StorageValue { mut owner, value } =
            db.get::<StorageValue>(storage_key)?.unwrap_or_default();
        if !value.is_zero() && owner.is_none() && self.should_have_owner(key) {
            owner = Some(self.address.address)
        }
        let storage_value = StorageValue { owner, value };
        self.storage_read_cache
            .write()
            .insert(key.to_vec(), storage_value.clone());
        Ok(storage_value)
    }

    pub fn transient_set_storage(&mut self, key: Vec<u8>, value: U256) {
        self.insert_transient_write_cache(key, value);
    }

    pub(super) fn should_have_owner(&self, _key: &[u8]) -> bool {
        self.address.space == Space::Native
            && self.address.address != SYSTEM_STORAGE_ADDRESS
    }

    pub fn change_storage_value(
        &mut self, db: &StateDbGeneric, key: &[u8], value: U256,
    ) -> DbResult<()> {
        let mut entry = self.storage_entry_at(db, key)?;
        if !entry.value.is_zero() {
            entry.value = value;
            self.insert_storage_write_cache(key.to_vec(), entry);
        } else {
            warn!("Change storage value outside transaction fails: current value is zero, tx {:?}, key {:?}", self.address, key);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn storage_layout_change(&self) -> Option<&StorageLayout> {
        self.storage_layout_change.as_ref()
    }

    #[cfg(test)]
    pub fn set_storage_layout(&mut self, layout: StorageLayout) {
        self.storage_layout_change = Some(layout);
    }
}

fn decode_storage_key(key: &Vec<u8>) -> Option<Vec<u8>> {
    if let StorageKeyWithSpace {
        key: StorageKey::StorageKey { storage_key, .. },
        ..
    } = StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key[..])
    {
        Some(storage_key.to_vec())
    } else {
        // Should be unreachable
        None
    }
}
