use super::{RequireFields, State};
use crate::try_loaded;
use cfx_bytes::Bytes;
use cfx_statedb::Result as DbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, H256, U256,
};
use keccak_hash::KECCAK_EMPTY;
use primitives::extract_7702_payload;
#[cfg(test)]
use primitives::StorageLayout;
use std::sync::Arc;

impl State {
    pub fn exists(&self, address: &AddressWithSpace) -> DbResult<bool> {
        Ok(self.read_account_lock(address)?.is_some())
    }

    /// Touch an account to mark it as warm
    pub fn touch(&self, address: &AddressWithSpace) -> DbResult<()> {
        self.exists(address)?;
        Ok(())
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
    ) -> DbResult<()> {
        // Mark address as warm.
        self.touch(address)?;

        // The caller should guarantee the validity of address.

        if !by.is_zero() {
            self.write_account_or_new_lock(address)?.add_balance(by);
        }

        Ok(())
    }

    pub fn sub_balance(
        &mut self, address: &AddressWithSpace, by: &U256,
    ) -> DbResult<()> {
        // Mark address as warm.
        self.touch(address)?;

        if !by.is_zero() {
            self.write_account_lock(address)?.sub_balance(by);
        }
        Ok(())
    }

    pub fn transfer_balance(
        &mut self, from: &AddressWithSpace, to: &AddressWithSpace, by: &U256,
    ) -> DbResult<()> {
        self.sub_balance(from, by)?;
        self.add_balance(to, by)?;
        Ok(())
    }

    pub fn nonce(&self, address: &AddressWithSpace) -> DbResult<U256> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(*acc.nonce())
    }

    pub fn inc_nonce(&mut self, address: &AddressWithSpace) -> DbResult<bool> {
        Ok(self.write_account_or_new_lock(address)?.inc_nonce())
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

    pub fn is_eip684_empty(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool> {
        let Some(acc) = self.read_account_lock(address)? else {
            return Ok(true);
        };
        Ok(acc.code_hash() == KECCAK_EMPTY && acc.nonce().is_zero())
    }

    pub fn is_eip158_empty(
        &self, address: &AddressWithSpace,
    ) -> DbResult<bool> {
        let Some(acc) = self.read_account_lock(address)? else {
            return Ok(true);
        };
        Ok(acc.code_hash() == KECCAK_EMPTY
            && acc.nonce().is_zero()
            && acc.balance().is_zero())
    }

    pub fn code_hash(&self, address: &AddressWithSpace) -> DbResult<H256> {
        let acc = try_loaded!(self.read_account_lock(address));
        Ok(acc.code_hash())
    }

    pub fn has_no_code(&self, address: &AddressWithSpace) -> DbResult<bool> {
        let Some(acc) = self.read_account_lock(address)? else {
            return Ok(true);
        };
        Ok(acc.code_hash() == KECCAK_EMPTY)
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

    pub fn code_with_hash_on_call(
        &self, address: &AddressWithSpace,
    ) -> DbResult<(Option<Arc<Vec<u8>>>, H256)> {
        let authority_acc = try_loaded!(
            self.read_account_ext_lock(address, RequireFields::Code)
        );
        let authority_code = authority_acc.code();
        let authority_code_hash = authority_acc.code_hash();

        std::mem::drop(authority_acc);

        let (code, code_hash) = if address.space == Space::Native {
            // Core space does not support-7702
            (authority_code, authority_code_hash)
        } else if let Some(delegated_address) = authority_code
            .as_ref()
            .and_then(|x| extract_7702_payload(&**x))
        {
            let delegated_acc = try_loaded!(self.read_account_ext_lock(
                &delegated_address.with_space(address.space),
                RequireFields::Code
            ));
            (delegated_acc.code(), delegated_acc.code_hash())
        } else {
            (authority_code, authority_code_hash)
        };

        Ok((code, code_hash))
    }

    pub fn init_code(
        &mut self, address: &AddressWithSpace, code: Bytes, owner: Address,
        transaction_hash: H256,
    ) -> DbResult<()> {
        self.write_account_lock(address)?.init_code(
            code,
            owner,
            transaction_hash,
        );
        Ok(())
    }

    pub fn created_at_transaction(
        &self, address: &AddressWithSpace, transaction_hash: H256,
    ) -> DbResult<bool> {
        Ok(
            if let Some(acc) =
                self.read_account_ext_lock(&address, RequireFields::None)?
            {
                acc.create_transaction_hash() == Some(transaction_hash)
            } else {
                false
            },
        )
    }

    pub fn set_authorization(
        &mut self, authority: &AddressWithSpace, address: &Address,
    ) -> DbResult<()> {
        self.write_account_or_new_lock(authority)?
            .set_authorization(address);
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
