// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[allow(unused)]
pub struct StateObjectCache {
    // TODO: at this moment this is fixed to 0 (no cache size limit).
    //  To limit the cache size we must remember to obtain the list of
    //  all updated account for the transaction pool.
    max_cache_size: usize,
    account_cache: HashMap<AccountAddress, CachedAccount>,
    // TODO: etc.
}

impl StateObjectCache {
    pub fn clear(&mut self) {
        self.account_cache.clear();
        // TODO: etc.
    }

    pub fn get_account(
        &self, address: &Address,
    ) -> Result<Option<&CachedAccount>> {
        match self.account_cache.get(address) {
            None => {
                // TODO: load from db.
                Ok(None)
            }
            Some(a) => Ok(Some(a)),
        }
    }
}

use crate::cache_object::{AccountAddress, CachedAccount};
use cfx_statedb::Result;
use cfx_types::Address;
use hashbrown::HashMap;
