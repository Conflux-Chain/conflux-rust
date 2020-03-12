// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, hash::KECCAK_EMPTY};
use cfx_types::{Address, H256, U256};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
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

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct StakingVoteInfo {
    /// This is the number of tokens should be locked before `unlock_time`.
    pub amount: U256,
    /// This is the timestamp when the vote right will be invalid, measured in
    /// the number of past blocks.
    pub unlock_time: u64,
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct CodeInfo {
    pub code: Bytes,
    pub owner: Address,
}

#[derive(Default, Clone, Debug, RlpDecodable, RlpEncodable)]
pub struct StorageValue {
    pub value: H256,
    pub owner: Address,
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,
    /// This is the number of tokens used in staking.
    pub staking_balance: U256,
    /// This is the number of tokens used as collateral for storage, which will
    /// be returned to balance if the storage is released.
    pub collateral_for_storage: U256,
    /// This is the accumulated interest return.
    pub accumulated_interest_return: U256,
    /// This is the list of deposit info, sorted in increasing order of
    /// `deposit_time`.
    pub deposit_list: Vec<DepositInfo>,
    /// This is the list of vote info. The `unlock_time` sorted in increasing
    /// order and the `amount` is sorted in decreasing order. All the
    /// `unlock_time` and `amount` is unique in the list.
    pub staking_vote_list: Vec<StakingVoteInfo>,
    /// This is the address of the administrator of the contract.
    pub admin: Address,
    /// This is the address of the sponsor of the contract.
    pub sponsor: Address,
    /// This is the amount of tokens sponsor to the contract.
    pub sponsor_balance: U256,
}

impl Account {
    pub fn new_empty_with_balance(
        address: &Address, balance: &U256, nonce: &U256,
    ) -> Account {
        Self {
            address: *address,
            balance: *balance,
            nonce: *nonce,
            code_hash: KECCAK_EMPTY,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            deposit_list: Vec::new(),
            staking_vote_list: Vec::new(),
            admin: Address::zero(),
            sponsor: Address::zero(),
            sponsor_balance: U256::zero(),
        }
    }
}
