use super::{OverlayAccount, State};
use cfx_statedb::Result as DbResult;
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
        let account = OverlayAccount::new_contract_with_admin(
            contract,
            balance,
            admin,
            invalidated_storage,
            storage_layout,
            cip107,
        );
        self.insert_to_cache(account);
        Ok(())
    }

    pub fn remove_contract(
        &mut self, address: &AddressWithSpace,
    ) -> DbResult<()> {
        self.insert_to_cache(OverlayAccount::new_removed(address));

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
        let account = OverlayAccount::new_contract(
            &contract.address,
            balance,
            invalidated_storage,
            Some(STORAGE_LAYOUT_REGULAR_V0),
        );
        self.insert_to_cache(account);
        Ok(())
    }
}
