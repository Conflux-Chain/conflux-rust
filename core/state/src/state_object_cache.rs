// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[allow(unused)]
pub struct StateObjectCache {
    // TODO: at this moment this is fixed to 0 (no cache size limit).
    //  To limit the cache size we must remember to obtain the list of
    //  all updated account for the transaction pool.
    max_cache_size: usize,
    account_cache: RwLock<HashMap<AccountAddress, CachedAccount>>,
    // TODO: etc.
}

impl StateObjectCache {
    pub fn clear(&mut self) {
        self.account_cache.get_mut().clear();
        // TODO: etc.
    }

    pub fn get_account<StateDb: StateDbExt>(
        &self, address: &Address, _db: &StateDb,
    ) -> Result<
        GuardedValue<
            RwLockReadGuard<HashMap<AccountAddress, CachedAccount>>,
            NonCopy<Option<&CachedAccount>>,
        >,
    > {
        let read_lock = self.account_cache.read();
        let (read_lock, derefed) = GuardedValue::new_derefed(read_lock).into();
        match derefed.get(address) {
            None => {
                // TODO: load from db.
                Ok(GuardedValue::new(read_lock, NonCopy(None)))
            }
            Some(a) => Ok(GuardedValue::new(read_lock, NonCopy(Some(a)))),
        }
    }
}

use crate::cache_object::{AccountAddress, CachedAccount};
use cfx_statedb::{Result, StateDbExt};
use cfx_storage::utils::guarded_value::{GuardedValue, NonCopy};
use cfx_types::Address;
use parking_lot::{RwLock, RwLockReadGuard};
use std::collections::HashMap;
