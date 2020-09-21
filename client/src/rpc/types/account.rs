// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H160, H256, U256};
use primitives::{
    Account as PrimitiveAccount, SponsorInfo as PrimitiveSponsorInfo,
};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,
    pub staking_balance: U256,
    pub collateral_for_storage: U256,
    pub accumulated_interest_return: U256,
    pub admin: H160,
}

impl Account {
    pub fn new(account: PrimitiveAccount) -> Self {
        Self {
            balance: account.balance.into(),
            nonce: account.nonce.into(),
            code_hash: account.code_hash.into(),
            staking_balance: account.staking_balance.into(),
            collateral_for_storage: account.collateral_for_storage.into(),
            accumulated_interest_return: account
                .accumulated_interest_return
                .into(),
            admin: account.admin.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SponsorInfo {
    pub sponsor_for_gas: H160,
    pub sponsor_for_collateral: H160,
    pub sponsor_gas_bound: U256,
    pub sponsor_balance_for_gas: U256,
    pub sponsor_balance_for_collateral: U256,
}

impl SponsorInfo {
    pub fn new(sponsor_info: PrimitiveSponsorInfo) -> Self {
        Self {
            sponsor_for_gas: sponsor_info.sponsor_for_gas.into(),
            sponsor_for_collateral: sponsor_info.sponsor_for_collateral.into(),
            sponsor_gas_bound: sponsor_info.sponsor_gas_bound.into(),
            sponsor_balance_for_gas: sponsor_info
                .sponsor_balance_for_gas
                .into(),
            sponsor_balance_for_collateral: sponsor_info
                .sponsor_balance_for_collateral
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::types::{Account, SponsorInfo};
    use cfx_types::{H160, H256, U256};
    use primitives::{
        Account as PrimitiveAccount, SponsorInfo as PrimitiveSponsorInfo,
    };

    #[test]
    fn test_account_new() {
        let pri_account = PrimitiveAccount::new_empty_with_balance(
            &H160([0x00; 20]),
            &U256::zero(),
            &U256::zero(),
        )
        .unwrap();
        let account = Account::new(pri_account);
        let account_info = serde_json::to_string(&account).unwrap();
        assert_eq!(account_info,
                   "{\"balance\":\"0x0\",\"nonce\":\"0x0\",\"codeHash\":\"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\",\"stakingBalance\":\"0x0\",\"collateralForStorage\":\"0x0\",\"accumulatedInterestReturn\":\"0x0\",\"admin\":\"0x0000000000000000000000000000000000000000\"}");
    }
    #[test]
    fn test_account_serialize() {
        let account = Account {
            balance: U256::one(),
            nonce: U256::one(),
            code_hash: H256([0xff; 32]),
            staking_balance: U256::one(),
            collateral_for_storage: U256::one(),
            accumulated_interest_return: U256::one(),
            admin: H160([0xff; 20]),
        };
        let serialize = serde_json::to_string(&account).unwrap();
        assert_eq!(serialize,"{\"balance\":\"0x1\",\"nonce\":\"0x1\",\"codeHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"stakingBalance\":\"0x1\",\"collateralForStorage\":\"0x1\",\"accumulatedInterestReturn\":\"0x1\",\"admin\":\"0xffffffffffffffffffffffffffffffffffffffff\"}");
    }
    #[test]
    fn test_account_deserialize() {
        let account = Account {
            balance: U256::one(),
            nonce: U256::one(),
            code_hash: H256([0xff; 32]),
            staking_balance: U256::one(),
            collateral_for_storage: U256::one(),
            accumulated_interest_return: U256::one(),
            admin: H160([0xff; 20]),
        };
        let serialize = "{\"balance\":\"0x1\",\"nonce\":\"0x1\",\"codeHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"stakingBalance\":\"0x1\",\"collateralForStorage\":\"0x1\",\"accumulatedInterestReturn\":\"0x1\",\"admin\":\"0xffffffffffffffffffffffffffffffffffffffff\"}";
        let deserialize: Account = serde_json::from_str(serialize).unwrap();
        assert_eq!(deserialize, account);
    }
    #[test]
    fn test_sponsor_info_new() {
        let pri_sponsor_info = PrimitiveSponsorInfo {
            sponsor_for_gas: H160([0xff; 20]),
            sponsor_for_collateral: H160([0xff; 20]),
            sponsor_gas_bound: U256::one(),
            sponsor_balance_for_gas: U256::one(),
            sponsor_balance_for_collateral: U256::one(),
        };
        let sponsor_info = SponsorInfo::new(pri_sponsor_info);
        let sponsor_info_new = serde_json::to_string(&sponsor_info).unwrap();
        assert_eq!(sponsor_info_new,
        r#"{"sponsorForGas":"0xffffffffffffffffffffffffffffffffffffffff","sponsorForCollateral":"0xffffffffffffffffffffffffffffffffffffffff","sponsorGasBound":"0x1","sponsorBalanceForGas":"0x1","sponsorBalanceForCollateral":"0x1"}"#);
    }
}
