use super::{AccountEntry, OverlayAccount, State};
use cfx_statedb::Result as DbResult;
use cfx_storage::utils::access_mode;
use cfx_types::{
    Address, AddressSpaceUtil, AddressWithSpace, Space, H256, U256,
};
#[cfg(test)]
use primitives::storage::STORAGE_LAYOUT_REGULAR_V0;
use primitives::{Account, StorageLayout};

impl State {
    pub fn new_contract_with_admin(
        &mut self, contract: &AddressWithSpace, admin: &Address, balance: U256,
        storage_layout: Option<StorageLayout>, cip107: bool,
    ) -> DbResult<()>
    {
        assert!(contract.space == Space::Native || admin.is_zero());
        // Check if the new contract is deployed on a killed contract in the
        // same block.
        let invalidated_storage = self
            .read_account_lock(contract)?
            .map_or(false, |overlay| overlay.invalidated_storage());
        let account_entry = OverlayAccount::new_contract_with_admin(
            contract,
            balance,
            admin,
            invalidated_storage,
            storage_layout,
            cip107,
        )
        .into_dirty_entry();
        self.update_cache(contract, account_entry);
        Ok(())
    }

    pub fn remove_contract(
        &mut self, address: &AddressWithSpace,
    ) -> DbResult<()> {
        if address.space == Space::Native {
            let removed_whitelist = self
                .clear_contract_whitelist::<access_mode::Write>(
                    &address.address,
                )?;

            if !removed_whitelist.is_empty() {
                error!(
                "removed_whitelist here should be empty unless in unit tests."
            );
            }
        }

        self.update_cache(
            address,
            OverlayAccount::new_removed(address).into_dirty_entry(),
        );

        Ok(())
    }

    /// A special implementation to fix the bug in function
    /// `clean_account` while not changing the genesis result.
    pub fn genesis_special_clean_account(
        &mut self, address: &Address,
    ) -> DbResult<()> {
        let address = address.with_native_space();
        let mut account = Account::new_empty(&address);
        account.code_hash = H256::default();
        *&mut *self.write_account_or_new_lock(&address)? =
            OverlayAccount::from_loaded(&address, account);
        Ok(())
    }

    fn update_cache(
        &mut self, address: &AddressWithSpace, account: AccountEntry,
    ) {
        let is_dirty = account.is_dirty();
        let old_value = self.cache.get_mut().insert(*address, account);
        if is_dirty {
            if let Some(ref mut checkpoint) =
                self.checkpoints.get_mut().last_mut()
            {
                checkpoint.entry(*address).or_insert(old_value);
            }
        }
    }
}

impl State {
    #[cfg(test)]
    pub fn new_contract_with_code(
        &mut self, contract: &AddressWithSpace, balance: U256,
    ) -> DbResult<()> {
        self.new_contract(contract, balance)?;
        self.init_code(&contract, vec![0x12, 0x34], Address::zero())?;
        Ok(())
    }

    #[cfg(test)]
    pub fn new_contract(
        &mut self, contract: &AddressWithSpace, balance: U256,
    ) -> DbResult<()> {
        let invalidated_storage = self
            .read_account_lock(contract)?
            .map_or(false, |acc| acc.invalidated_storage());
        let account_entry = OverlayAccount::new_contract(
            &contract.address,
            balance,
            invalidated_storage,
            Some(STORAGE_LAYOUT_REGULAR_V0),
        )
        .into_dirty_entry();
        self.update_cache(contract, account_entry);
        Ok(())
    }
}
