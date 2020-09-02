use crate::{
    executive::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    state::OverlayAccount,
};
use cfx_statedb::{Result as StateDbResult, StateDb, StateDbExt};
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

    pub fn check_commission_privilege(
        &mut self, contract_address: &Address, user: &Address,
    ) -> bool {
        // Generate an ephemeral overlay account for query.
        OverlayAccount::new_account_basic(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )
        .check_commission_privilege(
            self.storage.as_ref(),
            contract_address,
            user,
        )
        .unwrap_or(false)
    }
}
