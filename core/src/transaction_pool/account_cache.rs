use crate::{
    executive::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    state::OverlayAccount,
    statedb::{Result as StateDbResult, StateDb, StateDbExt},
};
use cfx_types::{Address, U256};
use primitives::{storage::STORAGE_LAYOUT_REGULAR_V0, Account};
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
        OverlayAccount::new_basic(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            U256::from(0),
            U256::from(0),
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .check_commission_privilege(
            self.storage.as_ref(),
            contract_address,
            user,
        )
        .unwrap_or(false)
    }
}
