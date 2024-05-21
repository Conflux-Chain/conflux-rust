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
}

#[derive(Debug, Clone, Copy)]
pub enum ChargeCollateral {
    Normal,
    EstimateSender,
    EstimateSponsor,
}

impl TransactSettings {
    pub fn all_checks() -> Self {
        Self {
            charge_collateral: ChargeCollateral::Normal,
            charge_gas: true,
            check_epoch_bound: true,
            check_base_price: true,
        }
    }
}
