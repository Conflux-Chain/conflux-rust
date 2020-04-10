use crate::statedb::{Result as StateDbResult, StateDb};
use cfx_types::Address;
use primitives::Account;
use std::{collections::hash_map::HashMap, sync::Arc};

pub struct AccountCache {
    pub accounts: HashMap<Address, Account>,
    pub storage: Arc<StateDb>,
}

impl AccountCache {
    pub fn new(storage: Arc<StateDb>) -> Self {
        AccountCache {
            accounts: HashMap::new(),
            storage,
        }
    }

    pub fn get_account_mut(
        &mut self, address: &Address,
    ) -> StateDbResult<Option<&mut Account>> {
        if !self.accounts.contains_key(&address) {
            let account = self.storage.get_account(&address)?;
            if let Some(account) = account {
                self.accounts.insert((*address).clone(), account);
            }
        }
        Ok(self.accounts.get_mut(&address))
    }
}
