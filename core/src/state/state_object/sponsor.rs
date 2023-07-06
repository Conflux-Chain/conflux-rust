use cfx_parameters::{
    internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    staking::COLLATERAL_UNITS_PER_STORAGE_KEY,
};
use cfx_state::maybe_address;
use cfx_statedb::{
    global_params::{ConvertedStoragePoints, TotalIssued},
    Result as DbResult,
};
use cfx_storage::utils::access_mode;
use cfx_types::{Address, AddressSpaceUtil, Space, U256};
use primitives::{
    SkipInputCheck, SponsorInfo, StorageKey, StorageKeyWithSpace, StorageValue,
};
use std::collections::HashMap;

use super::{internal_contract::storage_point_prop, substate::Substate, State};

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
    ) -> DbResult<()>
    {
        let sponsor_not_change =
            *sponsor == self.sponsor_for_gas(address)?.unwrap_or_default();
        let balance_not_change =
            *sponsor_balance == self.sponsor_balance_for_gas(address)?;
        noop_if!(sponsor_not_change && balance_not_change);

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
        noop_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .add_sponsor_balance_for_gas(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

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
    ) -> DbResult<U256>
    {
        let sponsor_not_change = *sponsor
            == self.sponsor_for_collateral(address)?.unwrap_or_default();
        let balance_not_change =
            *sponsor_balance == self.sponsor_balance_for_collateral(address)?;
        noop_if!(sponsor_not_change && balance_not_change);

        let prop = if is_cip107 {
            self.get_system_storage(&storage_point_prop())?
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
        noop_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .add_sponsor_balance_for_collateral(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

        self.write_native_account_lock(&address)?
            .sub_sponsor_balance_for_collateral(by);

        Ok(())
    }

    // Whitelist

    pub fn check_contract_whitelist(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let acc = try_loaded!(self.read_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS
        ));
        acc.check_contract_whitelist(&self.db, contract_address, user)
    }

    pub fn add_to_contract_whitelist(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        info!("add_commission_privilege contract_address: {:?}, contract_owner: {:?}, user: {:?}", contract_address, contract_owner, user);

        self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?
        .add_to_contract_whitelist(
            contract_address,
            contract_owner,
            user,
        );

        Ok(())
    }

    pub fn remove_from_contract_whitelist(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?
        .remove_from_contract_whitelist(
            contract_address,
            contract_owner,
            user,
        );
        Ok(())
    }

    pub fn clear_contract_whitelist<AM: access_mode::AccessMode>(
        &mut self, address: &Address,
    ) -> DbResult<HashMap<Vec<u8>, Address>> {
        let mut storage_owner_map = HashMap::new();
        let key_values = self.db.delete_all::<AM>(
            StorageKey::new_storage_key(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                address.as_ref(),
            )
            .with_native_space(),
            /* debug_record = */ None,
        )?;
        for (key, value) in &key_values {
            if let StorageKeyWithSpace {
                key: StorageKey::StorageKey { storage_key, .. },
                space,
            } =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                assert_eq!(space, Space::Native);
                let storage_value =
                    rlp::decode::<StorageValue>(value.as_ref())?;
                let storage_owner = storage_value
                    .owner
                    .unwrap_or(SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS);
                storage_owner_map.insert(storage_key.to_vec(), storage_owner);
            }
        }

        let mut sponsor_internal_contract = self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?;
        // Then scan storage changes in cache.
        for (key, _value) in
            sponsor_internal_contract.storage_value_write_cache()
        {
            if key.starts_with(address.as_ref()) {
                if let Some(storage_owner) = sponsor_internal_contract
                    .original_ownership_at(&self.db, key)?
                {
                    storage_owner_map.insert(key.clone(), storage_owner);
                } else {
                    // The corresponding entry has been reset during transaction
                    // execution, so we do not need to handle it now.
                    storage_owner_map.remove(key);
                }
            }
        }
        if !AM::READ_ONLY {
            // Note removal of all keys in storage_value_read_cache and
            // storage_value_write_cache.
            for (key, _storage_owner) in &storage_owner_map {
                debug!("delete sponsor key {:?}", key);
                sponsor_internal_contract.set_storage(
                    key.clone(),
                    U256::zero(),
                    /* owner doesn't matter for 0 value */
                    Address::zero(),
                );
            }
        }

        Ok(storage_owner_map)
    }

    pub fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Substate,
    ) -> DbResult<()> {
        self.clear_contract_whitelist::<access_mode::Write>(address)?;

        // Process collateral for removed storage.
        // TODO: try to do it in a better way, e.g. first log the deletion
        //  somewhere then apply the collateral change.

        self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?
        .commit_ownership_change(&self.db, substate)?;

        let account_cache_read_guard = self.cache.read();
        let maybe_account = account_cache_read_guard
            .get(&address.with_native_space())
            .and_then(|acc| acc.account.as_ref());

        let storage_key_value = self.db.delete_all::<access_mode::Read>(
            StorageKey::new_storage_root_key(address).with_native_space(),
            None,
        )?;
        for (key, value) in &storage_key_value {
            if let StorageKeyWithSpace {
                key: StorageKey::StorageKey { storage_key, .. },
                space,
            } =
                StorageKeyWithSpace::from_key_bytes::<SkipInputCheck>(&key[..])
            {
                assert_eq!(space, Space::Native);
                // Check if the key has been touched. We use the local
                // information to find out if collateral refund is necessary
                // for touched keys.
                if maybe_account.map_or(true, |acc| {
                    acc.storage_value_write_cache().get(storage_key).is_none()
                }) {
                    let storage_value =
                        rlp::decode::<StorageValue>(value.as_ref())?;
                    // Must native space
                    let storage_owner =
                        storage_value.owner.as_ref().unwrap_or(address);
                    substate.record_storage_release(
                        storage_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
        }

        if let Some(acc) = maybe_account {
            // The current value isn't important because it will be deleted.
            for (key, _value) in acc.storage_value_write_cache() {
                if let Some(storage_owner) =
                    acc.original_ownership_at(&self.db, key)?
                {
                    substate.record_storage_release(
                        &storage_owner,
                        COLLATERAL_UNITS_PER_STORAGE_KEY,
                    );
                }
            }
        }
        Ok(())
    }
}
