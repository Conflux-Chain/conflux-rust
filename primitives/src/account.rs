// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::KECCAK_EMPTY;
use cfx_types::{Address, H256, U256};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct DepositInfo {
    pub amount: U256,
    pub deposit_time: u64,
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,
    /// This is the number of tokens in bank and part of this will be used for
    /// storage.
    pub bank_balance: U256,
    /// This is the number of tokens in bank used for storage.
    pub storage_balance: U256,
    /// This is the accumulated interest rate.
    pub bank_ar: U256,
    /// This is a list of deposit history (`amount`, `deposit_time`), in sorted
    /// order of `deposit_time`.
    pub deposit_list: Vec<DepositInfo>,
    // TODO: check if we need the storage root, and if so, implement.
    pub admin: Address,
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
            bank_balance: 0.into(),
            storage_balance: 0.into(),
            bank_ar: 0.into(),
            deposit_list: Vec::new(),
            admin: Address::zero(),
        }
    }
}
