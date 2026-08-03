use crate::executive_observer::ExecutiveObserver;

/// Transaction execution options.
pub struct TransactOptions<O: ExecutiveObserver> {
    pub observer: O,
    pub settings: TransactSettings,
}

impl Default for TransactOptions<()> {
    fn default() -> Self {
        Self {
            observer: (),
            settings: TransactSettings::all_checks(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransactSettings {
    pub charge_collateral: ChargeCollateral,
    pub charge_gas: bool,
    pub check_base_price: bool,
    pub check_epoch_bound: bool,
    pub forbid_eoa_with_code: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ChargeCollateral {
    /// Charge normal collateral.
    Normal,
    /// Estimate collateral which would be charged to the sender.
    /// This mode does not actually charge the sender.
    EstimateSender,
    /// Estimate collateral which would be charged to the sponsor.
    /// This mode does not actually charge the sponsor.
    EstimateSponsor,
}

impl TransactSettings {
    pub fn all_checks() -> Self {
        Self {
            charge_collateral: ChargeCollateral::Normal,
            charge_gas: true,
            check_epoch_bound: true,
            check_base_price: true,
            forbid_eoa_with_code: true,
        }
    }
}
