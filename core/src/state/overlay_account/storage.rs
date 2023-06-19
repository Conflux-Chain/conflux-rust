use super::Substate;

#[cfg(test)]
use super::StorageLayout;
use cfx_parameters::{
    internal_contract_addresses::SYSTEM_STORAGE_ADDRESS,
    staking::COLLATERAL_UNITS_PER_STORAGE_KEY,
};
use cfx_statedb::{Result as DbResult, StateDbExt, StateDbGeneric};
use cfx_types::{Address, AddressWithSpace, Space, U256};

use primitives::{StorageKey, StorageValue};
use std::{collections::HashMap, sync::Arc};

use super::OverlayAccount;

impl OverlayAccount {
    pub fn set_storage(&mut self, key: Vec<u8>, value: U256, owner: Address) {
        Arc::make_mut(&mut self.storage_value_write_cache)
            .insert(key.clone(), value);
        if self.address.space == Space::Ethereum
            || self.address.address == SYSTEM_STORAGE_ADDRESS
        {
            return;
        }
        let lv1_write_cache =
            Arc::make_mut(&mut self.storage_owner_lv1_write_cache);
        if value.is_zero() {
            lv1_write_cache.insert(key, None);
        } else {
            lv1_write_cache.insert(key, Some(owner));
        }
    }

    pub fn cached_storage_at(&self, key: &[u8]) -> Option<U256> {
        if let Some(value) = self.storage_value_write_cache.get(key) {
            return Some(value.clone());
        }
        if let Some(value) = self.storage_value_read_cache.read().get(key) {
            return Some(value.clone());
        }
        None
    }

    // If a contract is removed, and then some one transfer balance to it,
    // `storage_at` will return incorrect value. But this case should never
    // happens.
    pub fn storage_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<U256> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(value);
        }
        if self.fresh_storage() {
            Ok(U256::zero())
        } else {
            Self::get_and_cache_storage(
                &mut self.storage_value_read_cache.write(),
                Arc::make_mut(&mut *self.storage_owner_lv2_write_cache.write()),
                db,
                &self.address,
                key,
                true, /* cache_ownership */
            )
        }
    }

    pub fn storage_opt_at(
        &self, db: &StateDbGeneric, key: &[u8],
    ) -> DbResult<Option<U256>> {
        if let Some(value) = self.cached_storage_at(key) {
            return Ok(Some(value));
        }
        if self.fresh_storage() {
            Ok(None)
        } else {
            Ok(db
                .get::<StorageValue>(
                    StorageKey::new_storage_key(
                        &self.address.address,
                        key.as_ref(),
                    )
                    .with_space(self.address.space),
                )?
                .map(|v| v.value))
        }
    }

    fn get_and_cache_storage(
        storage_value_read_cache: &mut HashMap<Vec<u8>, U256>,
        storage_owner_lv2_write_cache: &mut HashMap<Vec<u8>, Option<Address>>,
        db: &StateDbGeneric, address: &AddressWithSpace, key: &[u8],
        cache_ownership: bool,
    ) -> DbResult<U256>
    {
        assert!(!storage_owner_lv2_write_cache.contains_key(key));
        let cache_ownership = cache_ownership
            && address.space == Space::Native
            && address.address != SYSTEM_STORAGE_ADDRESS;

        if let Some(value) = db.get::<StorageValue>(
            StorageKey::new_storage_key(&address.address, key.as_ref())
                .with_space(address.space),
        )? {
            storage_value_read_cache.insert(key.to_vec(), value.value);
            if cache_ownership {
                storage_owner_lv2_write_cache.insert(
                    key.to_vec(),
                    Some(match value.owner {
                        Some(owner) => owner,
                        None => address.address,
                    }),
                );
            }
            Ok(value.value)
        } else {
            storage_value_read_cache.insert(key.to_vec(), U256::zero());
            if cache_ownership {
                storage_owner_lv2_write_cache.insert(key.to_vec(), None);
            }
            Ok(U256::zero())
        }
    }

    /// Return the owner of `key` before this execution. If it is `None`, it
    /// means the value of the key is zero before this execution. Otherwise, the
    /// value of the key is nonzero.
    pub fn original_ownership_at(
        &self, db: &StateDbGeneric, key: &Vec<u8>,
    ) -> DbResult<Option<Address>> {
        self.address.assert_native();
        if let Some(value) = self.storage_owner_lv2_write_cache.read().get(key)
        {
            return Ok(value.clone());
        }
        if self.fresh_storage() {
            return Ok(None);
        }
        let storage_value_read_cache =
            &mut self.storage_value_read_cache.write();
        let storage_owner_lv2_write_cache =
            &mut *self.storage_owner_lv2_write_cache.write();
        let storage_owner_lv2_write_cache =
            Arc::make_mut(storage_owner_lv2_write_cache);
        Self::get_and_cache_storage(
            storage_value_read_cache,
            storage_owner_lv2_write_cache,
            db,
            &self.address,
            key,
            true, /* cache_ownership */
        )?;
        Ok(storage_owner_lv2_write_cache
            .get(key)
            .expect("key exists")
            .clone())
    }

    /// Return the storage change of each related account.
    /// Each account is associated with a pair of `(usize, usize)`. The first
    /// value means the number of keys occupied by this account in current
    /// execution. The second value means the number of keys released by this
    /// account in current execution.
    pub fn commit_ownership_change(
        &mut self, db: &StateDbGeneric, substate: &mut Substate,
    ) -> DbResult<()> {
        self.address.assert_native();
        if self.invalidated_storage {
            return Ok(());
        }
        if self.address.address == SYSTEM_STORAGE_ADDRESS {
            return Ok(());
        }
        let storage_owner_lv1_write_cache: Vec<_> =
            Arc::make_mut(&mut self.storage_owner_lv1_write_cache)
                .drain()
                .collect();
        for (k, current_owner_opt) in storage_owner_lv1_write_cache {
            // Get the owner of `k` before execution. If it is `None`, it means
            // the value of the key is zero before execution. Otherwise, the
            // value of the key is nonzero.
            let original_ownership_opt = self.original_ownership_at(db, &k)?;
            if original_ownership_opt != current_owner_opt {
                if let Some(original_owner) = original_ownership_opt.as_ref() {
                    // The key has released from previous owner.
                    substate.record_storage_release(
                        original_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
                if let Some(current_owner) = current_owner_opt.as_ref() {
                    // The owner has occupied a new key.
                    substate.record_storage_occupy(
                        current_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
            // Commit ownership change to `storage_owner_lv2_write_cache`.
            Arc::make_mut(self.storage_owner_lv2_write_cache.get_mut())
                .insert(k, current_owner_opt);
        }
        assert!(self.storage_owner_lv1_write_cache.is_empty());
        Ok(())
    }

    pub fn change_storage_value(
        &mut self, db: &StateDbGeneric, key: &[u8], value: U256,
    ) -> DbResult<()> {
        let current_value = self.storage_at(db, key)?;
        if !current_value.is_zero() {
            // Constraint requirement: if a key appears in value_write_cache, it
            // must be in owner_lv2_write cache. Safety: since
            // current value is non-zero, this key must appears in
            // lv2_write_cache because `storage_at` loaded it.
            Arc::make_mut(&mut self.storage_value_write_cache)
                .insert(key.to_vec(), value);
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

    // TODO: consider remove this function
    pub fn storage_value_write_cache(&self) -> &HashMap<Vec<u8>, U256> {
        &self.storage_value_write_cache
    }
}
