use super::{RequireFields, State};
use crate::{state::CleanupMode, try_loaded};
use cfx_bytes::Bytes;
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressWithSpace, Space, H256, U256,
};
use keccak_hash::KECCAK_EMPTY;
#[cfg(test)]
use primitives::StorageLayout;
use std::sync::Arc;

impl State {
    pub fn exists(&self, address: &AddressWithSpace) -> DbResult<bool> {
        Ok(self.read_account_lock(address)?.is_some())
    }

    pub fn exists_and_not_null(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(!acc.is_null())
    }

    pub fn balance(&self, address: &AddressWithSpace) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(*acc.balance())
    }

    pub fn add_balance(
        &mut self, address: &AddressWithSpace, by: &U256,
        cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        let exists = self.exists(address)?;

        // The caller should guarantee the validity of address.

        if !by.is_zero()
            || (cleanup_mode == CleanupMode::ForceCreate && !exists)
        {
            self.write_account_or_new_lock(address)?.add_balance(by);
        }

        // TODO: consider remove touched
        if let CleanupMode::TrackTouched(set) = cleanup_mode {
            if exists {
                set.insert(*address);
            }
        }
        Ok(())
    }

    pub fn sub_balance(
        &mut self, address: &AddressWithSpace, by: &U256,
        cleanup_mode: &mut CleanupMode,
    ) -> DbResult<()> {
        if !by.is_zero() {
            self.write_account_lock(address)?.sub_balance(by);
        }

        if let CleanupMode::TrackTouched(ref mut set) = *cleanup_mode {
            if self.exists(address)? {
                set.insert(*address);
            }
        }
        Ok(())
    }

    pub fn transfer_balance(
        &mut self, from: &AddressWithSpace, to: &AddressWithSpace, by: &U256,
        mut cleanup_mode: CleanupMode,
    ) -> DbResult<()> {
        self.sub_balance(from, by, &mut cleanup_mode)?;
        self.add_balance(to, by, cleanup_mode)?;
        Ok(())
    }

    pub fn nonce(&self, address: &AddressWithSpace) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(*acc.nonce())
    }

    pub fn inc_nonce(&mut self, address: &AddressWithSpace) -> DbResult<()> {
        self.write_account_or_new_lock(address)?.inc_nonce();
        Ok(())
    }

    pub fn set_nonce(
        &mut self, address: &AddressWithSpace, nonce: &U256,
    ) -> DbResult<()> {
        self.write_account_or_new_lock(address)?.set_nonce(&nonce);
        Ok(())
    }

    pub fn is_contract_with_code(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool> {
        if address.space == Space::Native
            && !address.address.is_contract_address()
        {
            return Ok(false);
        }

        let acc = try_loaded!(self.read_account_lock(address));
        Ok(acc.code_hash() != KECCAK_EMPTY)
    }

    pub fn code_hash(&self, address: &AddressWithSpace) -> DbResult<H256> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(acc.code_hash())
    }

    pub fn code_size(&self, address: &AddressWithSpace) -> DbResult<usize> {
        let acc = try_loaded!(
            self.read_account_ext_lock(address, RequireFields::Code)
        );
        Ok(acc.code_size())
    }

    pub fn code_owner(&self, address: &AddressWithSpace) -> DbResult<Address> {
        address.assert_native();
        let acc = try_loaded!(
            self.read_account_ext_lock(address, RequireFields::Code)
        );
        Ok(acc.code_owner())
    }

    pub fn code(
        &self, address: &AddressWithSpace,
    ) -> DbResult<Option<Arc<Vec<u8>>>> {
        let acc = try_loaded!(
            self.read_account_ext_lock(address, RequireFields::Code)
        );
        Ok(acc.code())
    }

    pub fn init_code(
        &mut self, address: &AddressWithSpace, code: Bytes, owner: Address,
    ) -> DbResult<()> {
        self.write_account_lock(address)?.init_code(code, owner);
        Ok(())
    }

    pub fn admin(&self, address: &Address) -> DbResult<Address> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(*acc.admin())
    }

    pub fn set_admin(
        &mut self, contract_address: &Address, admin: &Address,
    ) -> DbResult<()> {
        self.write_native_account_lock(&contract_address)?
            .set_admin(admin);
        Ok(())
    }

    #[cfg(test)]
    pub fn set_storage_layout(
        &mut self, address: &AddressWithSpace, layout: StorageLayout,
    ) -> DbResult<()> {
        self.write_account_lock(address)?.set_storage_layout(layout);
        Ok(())
    }
}
