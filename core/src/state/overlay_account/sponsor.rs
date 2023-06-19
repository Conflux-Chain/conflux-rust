use cfx_parameters::consensus::ONE_CFX_IN_DRIP;
use cfx_statedb::{Result as DbResult, StateDbGeneric};
use cfx_types::{Address, U256};
use primitives::SponsorInfo;

use super::OverlayAccount;

lazy_static! {
    static ref COMMISSION_PRIVILEGE_STORAGE_VALUE: U256 = U256::one();
    /// If we set this key, it means every account has commission privilege.
    pub static ref COMMISSION_PRIVILEGE_SPECIAL_KEY: Address = Address::zero();
}

impl OverlayAccount {
    pub fn sponsor_info(&self) -> &SponsorInfo { &self.sponsor_info }

    pub fn set_sponsor_for_gas(
        &mut self, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    )
    {
        self.address.assert_native();
        self.sponsor_info.sponsor_for_gas = *sponsor;
        self.sponsor_info.sponsor_balance_for_gas = *sponsor_balance;
        self.sponsor_info.sponsor_gas_bound = *upper_bound;
    }

    pub fn set_sponsor_for_collateral(
        &mut self, sponsor: &Address, sponsor_balance: &U256, prop: U256,
    ) -> U256 {
        self.address.assert_native();
        self.sponsor_info.sponsor_for_collateral = *sponsor;
        let inc = sponsor_balance
            .saturating_sub(self.sponsor_info.sponsor_balance_for_collateral);
        self.sponsor_info.sponsor_balance_for_collateral = *sponsor_balance;

        if self.sponsor_info.storage_points.is_some() && !inc.is_zero() {
            let converted_storage_point =
                inc * prop / (U256::from(ONE_CFX_IN_DRIP) + prop);
            self.sponsor_info.sponsor_balance_for_collateral -=
                converted_storage_point;
            self.sponsor_info.storage_points.as_mut().unwrap().unused +=
                converted_storage_point;
            converted_storage_point
        } else {
            U256::zero()
        }
    }

    pub fn add_sponsor_balance_for_gas(&mut self, by: &U256) {
        self.address.assert_native();
        self.sponsor_info.sponsor_balance_for_gas += *by;
    }

    pub fn sub_sponsor_balance_for_gas(&mut self, by: &U256) {
        self.address.assert_native();
        assert!(self.sponsor_info.sponsor_balance_for_gas >= *by);
        self.sponsor_info.sponsor_balance_for_gas -= *by;
    }

    pub fn add_sponsor_balance_for_collateral(&mut self, by: &U256) {
        self.address.assert_native();
        self.sponsor_info.sponsor_balance_for_collateral += *by;
    }

    pub fn sub_sponsor_balance_for_collateral(&mut self, by: &U256) {
        self.address.assert_native();
        assert!(self.sponsor_info.sponsor_balance_for_collateral >= *by);
        self.sponsor_info.sponsor_balance_for_collateral -= *by;
    }

    pub fn check_contract_whitelist(
        &self, db: &StateDbGeneric, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        let mut special_key = Vec::with_capacity(Address::len_bytes() * 2);
        special_key.extend_from_slice(contract_address.as_bytes());
        special_key
            .extend_from_slice(COMMISSION_PRIVILEGE_SPECIAL_KEY.as_bytes());
        let special_value = self.storage_at(db, &special_key)?;
        if !special_value.is_zero() {
            Ok(true)
        } else {
            let mut key = Vec::with_capacity(Address::len_bytes() * 2);
            key.extend_from_slice(contract_address.as_bytes());
            key.extend_from_slice(user.as_bytes());
            self.storage_at(db, &key).map(|x| !x.is_zero())
        }
    }

    /// Add commission privilege of `contract_address` to `user`.
    /// We set the value to some nonzero value which will be persisted in db.
    pub fn add_to_contract_whitelist(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    )
    {
        let mut key = Vec::with_capacity(Address::len_bytes() * 2);
        key.extend_from_slice(contract_address.as_bytes());
        key.extend_from_slice(user.as_bytes());
        self.set_storage(
            key,
            COMMISSION_PRIVILEGE_STORAGE_VALUE.clone(),
            contract_owner,
        );
    }

    /// Remove commission privilege of `contract_address` from `user`.
    /// We set the value to zero, and the key/value will be released at commit
    /// phase.
    pub fn remove_from_contract_whitelist(
        &mut self, contract_address: Address, contract_owner: Address,
        user: Address,
    )
    {
        let mut key = Vec::with_capacity(Address::len_bytes() * 2);
        key.extend_from_slice(contract_address.as_bytes());
        key.extend_from_slice(user.as_bytes());
        self.set_storage(key, U256::zero(), contract_owner);
    }
}
