use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
use cfx_state::maybe_address;
use cfx_statedb::{
    global_params::{ConvertedStoragePoint, TotalIssued},
    Result as DbResult,
};
use cfx_types::{Address, U256};
use primitives::SponsorInfo;

use super::super::State;

impl State {
    pub fn sponsor_info(
        &self, address: &Address,
    ) -> DbResult<Option<SponsorInfo>> {
        let acc = try_loaded!(self.read_native_account(address));
        Ok(Some(acc.sponsor_info().clone()))
    }

    // Sponsor for gas

    pub fn sponsor_for_gas(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        let acc = try_loaded!(self.read_native_account(address));
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

        self.write_native_account(&address)?.set_sponsor_for_gas(
            sponsor,
            sponsor_balance,
            upper_bound,
        );
        Ok(())
    }

    // Sponsor balance for gas

    pub fn sponsor_balance_for_gas(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account(address));
        Ok(acc.sponsor_info().sponsor_balance_for_gas)
    }

    pub fn add_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

        self.write_native_account(&address)?
            .add_sponsor_balance_for_gas(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_gas(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

        self.write_native_account(&address)?
            .sub_sponsor_balance_for_gas(by);
        Ok(())
    }

    // Sponsor gas bound

    pub fn sponsor_gas_bound(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account(address));
        Ok(acc.sponsor_info().sponsor_gas_bound)
    }

    // Sponsor for collateral

    pub fn sponsor_for_collateral(
        &self, address: &Address,
    ) -> DbResult<Option<Address>> {
        let acc = try_loaded!(self.read_native_account(address));
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
            self.storage_point_prop()?
        } else {
            U256::zero()
        };

        let converted_storage_points = self
            .write_native_account(&address)?
            .set_sponsor_for_collateral(sponsor, sponsor_balance, prop);

        *self.global_stat.val::<TotalIssued>() -= converted_storage_points;
        *self.global_stat.val::<ConvertedStoragePoint>() +=
            converted_storage_points;
        Ok(converted_storage_points)
    }

    // Sponsor balance for collateral

    pub fn sponsor_balance_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account(address));
        Ok(acc.sponsor_info().sponsor_balance_for_collateral)
    }

    pub fn add_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

        self.write_native_account(&address)?
            .add_sponsor_balance_for_collateral(by);
        Ok(())
    }

    pub fn sub_sponsor_balance_for_collateral(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<()> {
        noop_if!(by.is_zero());

        self.write_native_account(&address)?
            .sub_sponsor_balance_for_collateral(by);

        Ok(())
    }

    // Whitelist

    pub fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let acc = try_loaded!(self
            .read_native_account(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS));
        acc.check_commission_privilege(&self.db, contract_address, user)
    }

    pub fn add_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        info!("add_commission_privilege contract_address: {:?}, contract_owner: {:?}, user: {:?}", contract_address, contract_owner, user);

        self.write_native_account(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS)?
            .add_commission_privilege(contract_address, contract_owner, user);

        Ok(())
    }

    pub fn remove_commission_privilege(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    ) -> DbResult<()>
    {
        self.write_native_account(&SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS)?
            .remove_commission_privilege(
                contract_address,
                contract_owner,
                user,
            );
        Ok(())
    }
}
