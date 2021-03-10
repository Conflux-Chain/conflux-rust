use crate::{
    account::{Account, CodeInfo},
    hash::KECCAK_EMPTY,
    DepositList, SponsorInfo, StorageValue, VoteStakeList,
};
use cfx_types::{Address, U256};
use std::default::Default;

/// This trait checks whether a variable equals to initialization value.
/// For a variable equals to the initialization value, the world-state should
/// treat is as None value.
pub trait IsDefault {
    fn is_default(&self) -> bool;
}

impl IsDefault for Account {
    fn is_default(&self) -> bool {
        self.balance == U256::zero()
            && self.nonce == U256::zero()
            && self.code_hash == KECCAK_EMPTY
            && self.staking_balance == U256::zero()
            && self.collateral_for_storage == U256::zero()
            && self.accumulated_interest_return == U256::zero()
            && self.admin == Address::default()
            && self.sponsor_info == SponsorInfo::default()
    }
}

impl IsDefault for CodeInfo {
    fn is_default(&self) -> bool {
        self.code.len() == 0 && self.owner == Address::default()
    }
}

impl IsDefault for DepositList {
    fn is_default(&self) -> bool { self.0.is_empty() }
}

impl IsDefault for VoteStakeList {
    fn is_default(&self) -> bool { self.0.is_empty() }
}

impl IsDefault for StorageValue {
    fn is_default(&self) -> bool {
        self.value == U256::zero()
            && (self.owner == Some(Address::default()) || self.owner == None)
    }
}

impl IsDefault for U256 {
    fn is_default(&self) -> bool { self.is_zero() }
}
