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
#[cfg(test)]
mod tests {
    use crate::{
        is_default::IsDefault, Account, CodeInfo, DepositList, StorageValue,
        VoteStakeList,
    };
    use cfx_types::{Address, H160, U256};
    use std::sync::Arc;

    #[test]
    fn test_is_default() {
        let account = Account::new_empty_with_balance(
            &H160([0x00; 20]),
            &U256::zero(),
            &U256::zero(),
        )
        .unwrap();
        assert_eq!(account.is_default(), true);
        let code_info = CodeInfo {
            code: Arc::new(vec![]),
            owner: Default::default(),
        };
        assert_eq!(code_info.is_default(), true);
        let deposit_list = DepositList { 0: vec![] };
        assert_eq!(deposit_list.is_default(), true);
        let vote_stake_list = VoteStakeList { 0: vec![] };
        assert_eq!(vote_stake_list.is_default(), true);
        let storage_value = StorageValue {
            value: Default::default(),
            owner: None,
        };
        assert_eq!(storage_value.is_default(), true);
        let storage_value1 = StorageValue {
            value: Default::default(),
            owner: Some(Address::default()),
        };
        assert_eq!(storage_value1.is_default(), true);
        let u256 = U256::zero();
        assert_eq!(u256.is_default(), true);
    }
}
