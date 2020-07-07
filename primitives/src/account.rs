// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, hash::KECCAK_EMPTY};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

use std::ops::{Deref, DerefMut};

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
pub struct VoteStakeInfo {
    /// This is the number of tokens should be locked before
    /// `unlock_block_number`.
    pub amount: U256,
    /// This is the timestamp when the vote right will be invalid, measured in
    /// the number of past blocks.
    pub unlock_block_number: u64,
}

#[derive(Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct DepositList(pub Vec<DepositInfo>);

impl Encodable for DepositList {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_list(&self.0); }
}

impl Decodable for DepositList {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let deposit_vec = d.as_list()?;
        Ok(DepositList(deposit_vec))
    }
}

impl Deref for DepositList {
    type Target = Vec<DepositInfo>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for DepositList {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(Clone, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
pub struct VoteStakeList(pub Vec<VoteStakeInfo>);

impl Encodable for VoteStakeList {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_list(&self.0); }
}

impl Decodable for VoteStakeList {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let vote_vec = d.as_list()?;
        Ok(VoteStakeList(vote_vec))
    }
}

impl Deref for VoteStakeList {
    type Target = Vec<VoteStakeInfo>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for VoteStakeList {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[derive(
    Clone, Debug, RlpDecodable, RlpEncodable, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct CodeInfo {
    pub code: Bytes,
    pub owner: Address,
}

#[derive(
    Clone,
    Debug,
    RlpDecodable,
    RlpEncodable,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Default,
)]
pub struct SponsorInfo {
    /// This is the address of the sponsor for gas cost of the contract.
    pub sponsor_for_gas: Address,
    /// This is the address of the sponsor for collateral of the contract.
    pub sponsor_for_collateral: Address,
    /// This is the upper bound of sponsor gas cost per tx.
    pub sponsor_gas_bound: U256,
    /// This is the amount of tokens sponsor for gas cost to the contract.
    pub sponsor_balance_for_gas: U256,
    /// This is the amount of tokens sponsor for collateral to the contract.
    pub sponsor_balance_for_collateral: U256,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
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
    /// This is the address of the administrator of the contract.
    pub admin: Address,
    /// This is the sponsor information of the contract.
    pub sponsor_info: SponsorInfo,
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
            admin: Address::zero(),
            sponsor_info: Default::default(),
        }
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !(rlp.item_count()? == 6 || rlp.item_count()? == 9) {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let address: Address = rlp.val_at(0)?;
        if address.is_user_account_address() || address.is_builtin_address() {
            if rlp.item_count()? != 6 {
                return Err(DecoderError::RlpIncorrectListLen);
            }
            Ok(Self {
                address,
                balance: rlp.val_at(1)?,
                nonce: rlp.val_at(2)?,
                code_hash: KECCAK_EMPTY,
                staking_balance: rlp.val_at(3)?,
                collateral_for_storage: rlp.val_at(4)?,
                accumulated_interest_return: rlp.val_at(5)?,
                admin: Address::zero(),
                sponsor_info: Default::default(),
            })
        } else if address.is_contract_address() {
            // Note that, our implementation assumes that the set of serialized
            // fields of contract address is a *super-set* of the
            // fields of normal addresses. This is because we allow
            // send money to contract address and we will create a *normal*
            // address stub there to store its balance.
            if rlp.item_count()? != 9 {
                return Err(DecoderError::RlpIncorrectListLen);
            }
            Ok(Self {
                address,
                balance: rlp.val_at(1)?,
                nonce: rlp.val_at(2)?,
                code_hash: rlp.val_at(3)?,
                staking_balance: rlp.val_at(4)?,
                collateral_for_storage: rlp.val_at(5)?,
                accumulated_interest_return: rlp.val_at(6)?,
                admin: rlp.val_at(7)?,
                sponsor_info: rlp.val_at(8)?,
            })
        } else {
            panic!("other types of address are not supported yet.");
        }
    }
}

impl Encodable for Account {
    fn rlp_append(&self, stream: &mut RlpStream) {
        if self.address.is_user_account_address()
            || self.address.is_builtin_address()
        {
            stream
                .begin_list(6)
                .append(&self.address)
                .append(&self.balance)
                .append(&self.nonce)
                .append(&self.staking_balance)
                .append(&self.collateral_for_storage)
                .append(&self.accumulated_interest_return);
        } else if self.address.is_contract_address() {
            // Note that, our implementation assumes that the set of serialized
            // fields of contract address is a *super-set* of the
            // fields of normal addresses. This is because we allow
            // send money to contract address and we will create a *normal*
            // address stub there to store its balance.
            stream
                .begin_list(9)
                .append(&self.address)
                .append(&self.balance)
                .append(&self.nonce)
                .append(&self.code_hash)
                .append(&self.staking_balance)
                .append(&self.collateral_for_storage)
                .append(&self.accumulated_interest_return)
                .append(&self.admin)
                .append(&self.sponsor_info);
        } else {
            panic!("other types of address are not supported yet.");
        }
    }
}
