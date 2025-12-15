use cfx_parameters::consensus::ONE_CFX_IN_DRIP;
use cfx_types::U256;
use primitives::account::StoragePoints;

use super::OverlayAccount;

impl OverlayAccount {
    /// The collateral of an account, including the token collateral and the
    /// storage point collateral
    pub fn collateral_for_storage(&self) -> U256 {
        self.address.assert_native();
        self.token_collateral_for_storage()
            + self.storage_point_collateral_for_storage()
    }

    pub fn token_collateral_for_storage(&self) -> U256 {
        self.address.assert_native();
        self.collateral_for_storage
    }

    pub fn storage_point_collateral_for_storage(&self) -> U256 {
        self.address.assert_native();
        self.sponsor_info
            .storage_points
            .as_ref()
            .map_or(U256::zero(), |x| x.used)
    }

    pub fn add_collateral_for_storage(&mut self, by: &U256) -> U256 {
        self.address.assert_native();
        if self.is_contract() {
            self.charge_for_sponsored_collateral(*by)
        } else {
            self.sub_balance(by);
            self.collateral_for_storage += *by;
            U256::zero()
        }
    }

    pub fn sub_collateral_for_storage(&mut self, by: &U256) -> U256 {
        self.address.assert_native();
        assert!(self.collateral_for_storage >= *by);
        if self.is_contract() {
            self.refund_for_sponsored_collateral(*by)
        } else {
            self.add_balance(by);
            self.collateral_for_storage -= *by;
            U256::zero()
        }
    }

    fn charge_for_sponsored_collateral(&mut self, by: U256) -> U256 {
        assert!(self.is_contract());
        let charge_from_balance =
            std::cmp::min(self.sponsor_info.sponsor_balance_for_collateral, by);
        self.sponsor_info.sponsor_balance_for_collateral -= charge_from_balance;
        self.collateral_for_storage += charge_from_balance;

        let charge_from_points = by - charge_from_balance;
        if !charge_from_points.is_zero() {
            let storage_points = self
                .sponsor_info
                .storage_points
                .as_mut()
                .expect("Storage points should be non-zero");
            storage_points.unused -= charge_from_points;
            storage_points.used += charge_from_points;
        }
        charge_from_points
    }

    fn refund_for_sponsored_collateral(&mut self, by: U256) -> U256 {
        assert!(self.is_contract());
        let refund_from_points = std::cmp::min(
            self.sponsor_info
                .storage_points
                .as_ref()
                .map_or(U256::zero(), |x| x.used),
            by,
        );
        if !refund_from_points.is_zero() {
            let storage_points = self
                .sponsor_info
                .storage_points
                .as_mut()
                .expect("Storage points should be non-zero");
            storage_points.unused += refund_from_points;
            storage_points.used -= refund_from_points;
        }

        let refund_from_balance = by - refund_from_points;
        self.sponsor_info.sponsor_balance_for_collateral += refund_from_balance;
        self.collateral_for_storage -= refund_from_balance;

        refund_from_points
    }

    pub fn is_cip_107_initialized(&self) -> bool {
        self.sponsor_info.storage_points.is_some()
    }

    /// When CIP 107 is activated, half of the storage will coverte
    pub fn initialize_cip107(&mut self, prop: U256) -> (U256, U256) {
        assert!(self.is_contract());
        let total_collateral = self.sponsor_info.sponsor_balance_for_collateral
            + self.collateral_for_storage;
        let changed_storage_points =
            total_collateral * prop / (U256::from(ONE_CFX_IN_DRIP) + prop);
        let mut storage_points = StoragePoints {
            unused: changed_storage_points,
            used: U256::zero(),
        };

        let burnt_balance_from_balance = std::cmp::min(
            self.sponsor_info.sponsor_balance_for_collateral,
            changed_storage_points,
        );
        let burnt_balance_from_collateral =
            changed_storage_points - burnt_balance_from_balance;

        if !burnt_balance_from_balance.is_zero() {
            self.sponsor_info.sponsor_balance_for_collateral -=
                burnt_balance_from_balance;
        }
        if !burnt_balance_from_collateral.is_zero() {
            self.collateral_for_storage -= burnt_balance_from_collateral;
            storage_points.unused -= burnt_balance_from_collateral;
            storage_points.used += burnt_balance_from_collateral;
        }
        self.sponsor_info.storage_points = Some(storage_points);

        return (burnt_balance_from_balance, burnt_balance_from_collateral);
    }
}
