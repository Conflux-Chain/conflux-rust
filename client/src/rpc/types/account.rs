// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H160, H256, U256};
use primitives::{
    Account as PrimitiveAccount, DepositInfo as PrimitiveDepositInfo,
    SponsorInfo as PrimitiveSponsorInfo,
    VoteStakeInfo as PrimitiveVoteStakeInfo,
};

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositInfo {
    /// This is the number of tokens in this deposit.
    pub amount: U256,
    /// This is the timestamp when this deposit happened, measured in the
    /// number of past blocks. It will be used to calculate
    /// the service charge.
    pub deposit_time: u64,
    /// This is the accumulated interest rate when this deposit happened.
    pub accumulated_interest_rate: U256,
}

impl DepositInfo {
    pub fn new(deposit_info: PrimitiveDepositInfo) -> Self {
        Self {
            amount: deposit_info.amount,
            deposit_time: deposit_info.deposit_time,
            accumulated_interest_rate: deposit_info.accumulated_interest_rate,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteStakeInfo {
    /// This is the number of tokens should be locked before
    /// `unlock_block_number`.
    pub amount: U256,
    /// This is the timestamp when the vote right will be invalid, measured in
    /// the number of past blocks.
    pub unlock_block_number: u64,
}

impl VoteStakeInfo {
    pub fn new(vote_stake_info: PrimitiveVoteStakeInfo) -> Self {
        Self {
            amount: vote_stake_info.amount,
            unlock_block_number: vote_stake_info.unlock_block_number,
        }
    }
}
