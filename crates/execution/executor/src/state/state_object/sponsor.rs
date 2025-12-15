use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
use cfx_statedb::{
    access_mode,
    global_params::{ConvertedStoragePoints, TotalIssued},
    Result as DbResult,
};
use cfx_types::{
    maybe_address, Address, AddressSpaceUtil, AddressWithSpace, U256,
};
use primitives::{SponsorInfo, StorageKey};

use super::{State, Substate};
use crate::{return_if, try_loaded};

lazy_static! {
    static ref COMMISSION_PRIVILEGE_STORAGE_VALUE: U256 = U256::one();
    /// If we set this key, it means every account has commission privilege.
    pub static ref COMMISSION_PRIVILEGE_SPECIAL_KEY: Address = Address::zero();
}

impl State {
    pub fn sponsor_info(
        &self, address: &Address,
    ) -> DbResult<Option<SponsorInfo>> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(Some(acc.sponsor_info().clone()))
    }

    // Sponsor for gas

    pub fn sponsor_for_gas(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(maybe_address(&acc.sponsor_info().sponsor_for_gas))
    }

    pub fn set_sponsor_for_gas(
        &self, address: &Address, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) -> DbResult<()> {
        let sponsor_not_change =
            *sponsor == self.sponsor_for_gas(address)?.unwrap_or_default();
        let balance_not_change =
            *sponsor_balance == self.sponsor_balance_for_gas(address)?;
        return_if!(sponsor_not_change && balance_not_change);

        self.write_native_account_lock(&address)?
            .set_sponsor_for_gas(sponsor, sponsor_balance, upper_bound);
        Ok(())
    }

    // Sponsor balance for gas

    pub fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc.sponsor_info().sponsor_balance_for_gas)
    }

    pub fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        return_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .add_sponsor_balance_for_gas(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        return_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .sub_sponsor_balance_for_gas(by);
        Ok(())
    }

    // Sponsor gas bound

    pub fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc.sponsor_info().sponsor_gas_bound)
    }

    // Sponsor for collateral

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(maybe_address(&acc.sponsor_info().sponsor_for_collateral))
    }

    pub fn set_sponsor_for_collateral(
        &mut self, address: &Address, sponsor: &Address,
        sponsor_balance: &U256, is_cip107: bool,
    ) -> DbResult<U256> {
        let sponsor_not_change = *sponsor
            == self.sponsor_for_collateral(address)?.unwrap_or_default();
        let balance_not_change =
            *sponsor_balance == self.sponsor_balance_for_collateral(address)?;
        return_if!(sponsor_not_change && balance_not_change);

        let prop = if is_cip107 {
            self.storage_point_prop()?
        } else {
            U256::zero()
        };

        let converted_storage_points = self
            .write_native_account_lock(&address)?
            .set_sponsor_for_collateral(sponsor, sponsor_balance, prop);

        *self.global_stat.val::<TotalIssued>() -= converted_storage_points;
        *self.global_stat.val::<ConvertedStoragePoints>() +=
            converted_storage_points;
        Ok(converted_storage_points)
    }

    // Sponsor balance for collateral

    pub fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc.sponsor_info().sponsor_balance_for_collateral)
    }

    pub fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        return_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .add_sponsor_balance_for_collateral(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        return_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .sub_sponsor_balance_for_collateral(by);

        Ok(())
    }

    // Whitelist

    pub fn check_contract_whitelist(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let special_value = self.storage_at(
            &sponsor_address(),
            &special_sponsor_key(&contract_address),
        )?;
        if !special_value.is_zero() {
            Ok(true)
        } else {
            self.storage_at(
                &sponsor_address(),
                &sponsor_key(contract_address, user),
            )
            .map(|x| !x.is_zero())
        }
    }

    pub fn add_to_contract_whitelist(
        &mut self, contract_address: Address, storage_owner: Address,
        user: Address, substate: &mut Substate,
    ) -> DbResult<()> {
        info!(
            "add_commission_privilege contract_address: {:?}, user: {:?}",
            contract_address, user
        );

        self.set_storage(
            &sponsor_address(),
            sponsor_key(&contract_address, &user),
            COMMISSION_PRIVILEGE_STORAGE_VALUE.clone(),
            storage_owner,
            substate,
        )?;

        Ok(())
    }

    pub fn remove_from_contract_whitelist(
        &mut self, contract_address: Address, storage_owner: Address,
        user: Address, substate: &mut Substate,
    ) -> DbResult<()> {
        self.set_storage(
            &sponsor_address(),
            sponsor_key(&contract_address, &user),
            U256::zero(),
            storage_owner,
            substate,
        )?;

        Ok(())
    }

    pub fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Substate, cip131: bool,
    ) -> DbResult<()> {
        if !cip131 {
            storage_range_deletion_for_account(
                self,
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                address.as_ref(),
                substate,
            )?;
        }
        storage_range_deletion_for_account(self, address, &vec![], substate)?;
        Ok(())
    }

    #[cfg(test)]
    pub fn clear_contract_whitelist(
        &mut self, address: &Address, substate: &mut Substate,
    ) -> DbResult<()> {
        storage_range_deletion_for_account(
            self,
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            address.as_ref(),
            substate,
        )?;
        Ok(())
    }
}

#[inline]
fn sponsor_address() -> AddressWithSpace {
    SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS.with_native_space()
}

#[inline]
fn sponsor_key(contract: &Address, user: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(Address::len_bytes() * 2);
    key.extend_from_slice(contract.as_bytes());
    key.extend_from_slice(user.as_bytes());
    key
}

fn special_sponsor_key(contract: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(Address::len_bytes() * 2);
    key.extend_from_slice(contract.as_bytes());
    key.extend_from_slice(COMMISSION_PRIVILEGE_SPECIAL_KEY.as_bytes());
    key
}

fn storage_range_deletion_for_account(
    state: &mut State, address: &Address, key_prefix: &[u8],
    substate: &mut Substate,
) -> DbResult<()> {
    let delete_all = key_prefix.is_empty();

    let storage_key_prefix = if delete_all {
        StorageKey::new_storage_root_key(&address)
    } else {
        StorageKey::new_storage_key(&address, key_prefix)
    }
    .with_native_space();
    let db_deletion_log = state
        .db
        .delete_all::<access_mode::Read>(storage_key_prefix, None)?
        .into_iter();
    state
        .write_native_account_lock(address)?
        .delete_storage_range(db_deletion_log, key_prefix, substate)?;
    Ok(())
}
