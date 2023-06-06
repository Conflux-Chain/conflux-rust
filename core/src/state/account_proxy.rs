use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, H256, U256};
use primitives::Account;

use super::{account_entry::OverlayAccount, State};

macro_rules! try_loaded {
    ($expr:expr) => {
        match $expr {
            Err(e) => {
                return Err(e);
            }
            Ok(None) => {
                return Ok(Default::default());
            }
            Ok(Some(v)) => v,
        }
    };
}

macro_rules! noop_if {
    ($expr:expr) => {
        if $expr {
            return Ok(Default::default());
        }
    };
}

mod basic;
pub(super) mod collateral;
mod global_stat;
pub(super) mod pos;
mod sponsor;
pub(super) mod staking;

// System Storages
impl State {
    pub fn set_system_storage(
        &mut self, key: Vec<u8>, value: U256,
    ) -> DbResult<()> {
        self.set_storage(
            &SYSTEM_STORAGE_ADDRESS.with_native_space(),
            key,
            value,
            // The system storage data have no owner, and this parameter is
            // ignored.
            Default::default(),
        )
    }

    pub fn get_system_storage(&self, key: &[u8]) -> DbResult<U256> {
        self.storage_at(&SYSTEM_STORAGE_ADDRESS.with_native_space(), key)
    }

    pub fn get_system_storage_opt(&self, key: &[u8]) -> DbResult<Option<U256>> {
        let acc =
            try_loaded!(self.read_native_account(&SYSTEM_STORAGE_ADDRESS));
        acc.storage_opt_at(&self.db, key)
    }
}

// contract variable
impl State {
    pub fn storage_at(
        &self, address: &AddressWithSpace, key: &[u8],
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account(address));
        acc.storage_at(&self.db, key)
    }

    pub fn set_storage(
        &mut self, address: &AddressWithSpace, key: Vec<u8>, value: U256,
        owner: Address,
    ) -> DbResult<()>
    {
        if self.storage_at(address, &key)? != value {
            self.require_exists(address, false)?
                .set_storage(key, value, owner)
        }
        Ok(())
    }
}

impl State {
    // This is a special implementation to fix the bug in function
    // `clean_account` while not changing the genesis result.
    pub fn genesis_special_clean_account(
        &mut self, address: &Address,
    ) -> DbResult<()> {
        let address = address.with_native_space();
        let mut account = Account::new_empty(&address);
        account.code_hash = H256::default();
        *&mut *self.require_or_new_basic_account(&address)? =
            OverlayAccount::from_loaded(&address, account);
        Ok(())
    }

    pub fn clean_account(
        &mut self, address: &AddressWithSpace,
    ) -> DbResult<()> {
        *&mut *self.require_or_new_basic_account(address)? =
            OverlayAccount::from_loaded(address, Account::new_empty(address));
        Ok(())
    }
}
