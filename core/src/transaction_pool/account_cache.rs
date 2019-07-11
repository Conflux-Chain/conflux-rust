use crate::{statedb::StateDb, storage::Storage};
use cfx_types::Address;
use primitives::Account;
use std::collections::hash_map::HashMap;

pub struct AccountCache<'storage> {
    pub accounts: HashMap<Address, Account>,
    pub storage: StateDb<'storage>,
}

impl<'storage> AccountCache<'storage> {
    pub fn new(storage: Storage<'storage>) -> Self {
        AccountCache {
            accounts: HashMap::new(),
            storage: StateDb::new(storage),
        }
    }

    pub fn get_account_mut(
        &mut self, address: &Address,
    ) -> Option<&mut Account> {
        if !self.accounts.contains_key(&address) {
            let account =
                self.storage.get_account(&address).ok().and_then(|x| x);
            if let Some(account) = account {
                self.accounts.insert((*address).clone(), account);
            }
        }
        self.accounts.get_mut(&address)
    }
}
