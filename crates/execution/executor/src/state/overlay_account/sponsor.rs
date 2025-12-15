use cfx_parameters::consensus::ONE_CFX_IN_DRIP;
use cfx_types::{Address, U256};
use primitives::SponsorInfo;

use super::OverlayAccount;

impl OverlayAccount {
    pub fn sponsor_info(&self) -> &SponsorInfo { &self.sponsor_info }

    pub fn set_sponsor_for_gas(
        &mut self, sponsor: &Address, sponsor_balance: &U256,
        upper_bound: &U256,
    ) {
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
}
