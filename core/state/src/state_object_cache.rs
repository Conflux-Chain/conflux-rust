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
    // TODO: etc.
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

        // Load from db.
        let mut write_lock = cache.write();
        if !write_lock.contains_key(key) {
            let hash_key = Key::to_hash_key(key);
            let loaded = Value::load(&hash_key, db)?;
            write_lock.insert(hash_key, loaded);
        }
        let (read_lock, derefed) =
            GuardedValue::new_derefed(RwLockWriteGuard::downgrade(write_lock))
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
}

use crate::{
    cache_object::{CachedAccount, CachedObject, ToHashKey},
    StateDbOps,
};
use cfx_statedb::Result;
use cfx_storage::utils::guarded_value::{GuardedValue, NonCopy};
use cfx_types::Address;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{borrow::Borrow, collections::HashMap, hash::Hash};
