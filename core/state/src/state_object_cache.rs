// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[allow(unused)]
pub struct StateObjectCache {
    // TODO: at this moment this is fixed to 0 (no cache size limit).
    //  To limit the cache size we must remember to obtain the list of
    //  all updated account for the transaction pool.
    max_cache_size: usize,
    account_cache: RwLock<HashMap<Address, Option<CachedAccount>>>,
    code_cache: RwLock<HashMap<CodeAddress, Option<CodeInfo>>>,
    // TODO: etc.
}

pub struct ModifyAndUpdate<'a, StateDb: StateDbOps, T: CachedObject> {
    db: &'a mut StateDb,
    key: T::HashKeyType,
    value: &'a mut Option<T>,
    debug_record: Option<&'a mut ComputeEpochDebugRecord>,
}

impl<'a, StateDb: StateDbOps, T: CachedObject> ModifyAndUpdate<'a, StateDb, T> {
    // Note: if a value exists, the ModifyAndUpdate object will be "finalized"
    // before exit.
    pub fn map_or_else<
        D: FnOnce() -> Result<U>,
        F: FnOnce(&mut T) -> Result<U>,
        U,
    >(
        &mut self, default: D, f: F,
    ) -> Result<U> {
        match self.value {
            None => default(),
            Some(value) => {
                let result = f(value);
                self.finalize()?;
                result
            }
        }
    }

    pub fn finalize(&mut self) -> Result<()> {
        match self.value {
            None => {
                T::delete(&self.key, self.db, self.debug_record.as_deref_mut())?
            }
            Some(value) => value.update(
                &self.key,
                self.db,
                self.debug_record.as_deref_mut(),
            )?,
        }
        Ok(())
    }
}

impl<'a, StateDb: StateDbOps, T: CachedObject> Drop
    for ModifyAndUpdate<'a, StateDb, T>
{
    fn drop(&mut self) {
        unreachable!(
            "User should always call the finalize \
             method to propogate the potential db error."
        );
    }
}

impl StateObjectCache {
    pub fn clear(&mut self) {
        self.account_cache.get_mut().clear();
        // TODO: etc.
    }

    fn ensure_loaded<
        'c,
        StateDb: StateDbOps,
        Value: CachedObject,
        Key: Hash + Eq + ToHashKey<<Value as CachedObject>::HashKeyType>,
    >(
        cache: &'c RwLock<
            HashMap<<Value as CachedObject>::HashKeyType, Option<Value>>,
        >,
        key: &Key, db: &StateDb,
    ) -> Result<
        GuardedValue<
            RwLockReadGuard<
                'c,
                HashMap<<Value as CachedObject>::HashKeyType, Option<Value>>,
            >,
            NonCopy<Option<&'c Value>>,
        >,
    >
    where
        <Value as CachedObject>::HashKeyType: Eq + Hash + Borrow<Key>,
    {
        // Return immediately when there is no need to have db operation.
        {
            let (read_lock, derefed) =
                GuardedValue::new_derefed(cache.read()).into();
            if let Some(value) = derefed.get(key) {
                return Ok(GuardedValue::new(
                    read_lock,
                    NonCopy(value.as_ref()),
                ));
            }
        }

        // Hold an upgradable read lock while loading db for better performance.
        let upgradable_read_lock = cache.upgradable_read();
        if !upgradable_read_lock.contains_key(key) {
            let hash_key = Key::to_hash_key(key);
            let loaded = Value::load(&hash_key, db)?;
            let mut write_lock =
                RwLockUpgradableReadGuard::upgrade(upgradable_read_lock);
            write_lock.insert(hash_key, loaded);

            let (read_lock, derefed) = GuardedValue::new_derefed(
                RwLockWriteGuard::downgrade(write_lock),
            )
            .into();
            Ok(GuardedValue::new(
                read_lock,
                NonCopy(
                    derefed
                        .get(key)
                        .map_or(None, |value_optional| value_optional.as_ref()),
                ),
            ))
        } else {
            let (read_lock, derefed) = GuardedValue::new_derefed(
                RwLockUpgradableReadGuard::downgrade(upgradable_read_lock),
            )
            .into();
            Ok(GuardedValue::new(
                read_lock,
                NonCopy(
                    derefed
                        .get(key)
                        .map_or(None, |value_optional| value_optional.as_ref()),
                ),
            ))
        }
    }

    fn require_or_set<
        'c,
        StateDb: StateDbOps,
        Value: CachedObject,
        Key: Hash + Eq + ToHashKey<<Value as CachedObject>::HashKeyType>,
        F,
    >(
        cache: &'c RwLock<
            HashMap<<Value as CachedObject>::HashKeyType, Option<Value>>,
        >,
        key: &Key, db: &'c mut StateDb, default: F,
        debug_record: Option<&'c mut ComputeEpochDebugRecord>,
    ) -> Result<
        GuardedValue<
            RwLockWriteGuard<
                'c,
                HashMap<<Value as CachedObject>::HashKeyType, Option<Value>>,
            >,
            ModifyAndUpdate<'c, StateDb, /* TODO: Key, */ Value>,
        >,
    >
    where
        <Value as CachedObject>::HashKeyType: Eq + Hash + Borrow<Key>,
        F: FnOnce(&Key) -> Result<Option<Value>>,
    {
        let upgradable_read_lock = cache.upgradable_read();
        let mut write_lock;
        if !upgradable_read_lock.contains_key(key) {
            let hash_key = Key::to_hash_key(key);
            let loaded = Value::load(&hash_key, db)?;
            write_lock =
                RwLockUpgradableReadGuard::upgrade(upgradable_read_lock);
            write_lock.insert(hash_key, loaded);
        } else {
            write_lock =
                RwLockUpgradableReadGuard::upgrade(upgradable_read_lock);
        }

        let (write_lock, deref) =
            GuardedValue::new_derefed_mut(write_lock).into();
        let value = deref
            .get_mut(key)
            .expect("entry known to exist in the cache");

        if value.is_none() {
            *value = default(key)?;
        }

        Ok(GuardedValue::new(
            write_lock,
            ModifyAndUpdate {
                db,
                key: key.to_hash_key(),
                value,
                debug_record,
            },
        ))
    }

    pub fn get_account<StateDb: StateDbOps>(
        &self, address: &Address, db: &StateDb,
    ) -> Result<
        GuardedValue<
            RwLockReadGuard<HashMap<Address, Option<CachedAccount>>>,
            NonCopy<Option<&CachedAccount>>,
        >,
    > {
        Self::ensure_loaded(&self.account_cache, address, db)
    }

    pub fn modify_and_update_account<'a, StateDb: StateDbOps>(
        &'a self, address: &Address, db: &'a mut StateDb,
        debug_record: Option<&'a mut ComputeEpochDebugRecord>,
    ) -> Result<
        GuardedValue<
            RwLockWriteGuard<HashMap<Address, Option<CachedAccount>>>,
            ModifyAndUpdate<StateDb, /* TODO: Key, */ CachedAccount>,
        >,
    >
    {
        Self::require_or_set(
            &self.account_cache,
            address,
            db,
            |_addr| Ok(None),
            debug_record,
        )
    }

    pub fn get_code<StateDb: StateDbOps>(
        &self, contract_address: &Address, db: &StateDb,
    ) -> Result<
        GuardedValue<
            RwLockReadGuard<HashMap<CodeAddress, Option<CodeInfo>>>,
            NonCopy<Option<&CodeInfo>>,
        >,
    > {
        let code_hash;
        {
            match self.get_account(contract_address, db)?.as_ref().as_ref() {
                None => {
                    return Ok(GuardedValue::new(
                        self.code_cache.read(),
                        NonCopy(None),
                    ));
                }
                Some(account) => {
                    code_hash = account.code_hash.clone();
                    if code_hash.is_zero() {
                        return Ok(GuardedValue::new(
                            self.code_cache.read(),
                            NonCopy(None),
                        ));
                    }
                }
            }
        }
        Self::ensure_loaded(
            &self.code_cache,
            &CodeAddress(*contract_address, code_hash),
            db,
        )
    }
}

use crate::{
    cache_object::{CachedAccount, CachedObject, CodeAddress, ToHashKey},
    StateDbOps,
};
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::Result;
use cfx_storage::utils::guarded_value::{GuardedValue, NonCopy};
use cfx_types::Address;
use parking_lot::{
    RwLock, RwLockReadGuard, RwLockUpgradableReadGuard, RwLockWriteGuard,
};
use primitives::CodeInfo;
use std::{borrow::Borrow, collections::HashMap, hash::Hash};
