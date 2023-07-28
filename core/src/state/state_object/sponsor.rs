use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
use cfx_state::maybe_address;
use cfx_statedb::{
    global_params::{ConvertedStoragePoints, TotalIssued},
    Result as DbResult,
};
use cfx_storage::utils::access_mode;
use cfx_types::{Address, U256};
use primitives::{SponsorInfo, StorageKey};

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
        &mut self, contract_address: Address, storage_owner: Address,
        user: Address, substate: &mut Substate,
    ) -> DbResult<()>
    {
        info!(
            "add_commission_privilege contract_address: {:?}, user: {:?}",
            contract_address, user
        );

        self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?
        .add_to_contract_whitelist(
            &self.db,
            contract_address,
            user,
            storage_owner,
            substate,
        )?;

        Ok(())
    }

    pub fn remove_from_contract_whitelist(
        &mut self, contract_address: Address, storage_owner: Address,
        user: Address, substate: &mut Substate,
    ) -> DbResult<()>
    {
        self.write_native_account_lock(
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        )?
        .remove_from_contract_whitelist(
            &self.db,
            contract_address,
            user,
            storage_owner,
            substate,
        )?;
        Ok(())
    }

    pub fn record_storage_and_whitelist_entries_release(
        &mut self, address: &Address, substate: &mut Substate,
    ) -> DbResult<()> {
        storage_range_deletion_for_account(
            self,
            &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
            address.as_ref(),
            substate,
        )?;
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

fn storage_range_deletion_for_account(
    state: &mut State, address: &Address, key_prefix: &[u8],
    substate: &mut Substate,
) -> DbResult<()>
{
    let delete_all = key_prefix.is_empty();

    let storage_key_prefix = if delete_all {
        StorageKey::new_storage_root_key(&address)
    } else {
        StorageKey::new_storage_key(&address, key_prefix)
    }
    .with_native_space();
    let deletion_log = state
        .db
        .delete_all::<access_mode::Write>(storage_key_prefix, None)?
        .into_iter();
    state
        .write_native_account_lock(address)?
        .delete_storage_range(deletion_log, address.as_ref(), substate)?;
    Ok(())
}
