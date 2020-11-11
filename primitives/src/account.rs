// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{bytes::Bytes, hash::KECCAK_EMPTY};
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::{Deserialize, Serialize};

use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::Arc,
};

#[derive(Debug, PartialEq, Clone)]
pub enum AddressSpace {
    Builtin,
    User,
    Contract,
}

#[derive(Debug, PartialEq, Clone)]
pub enum AccountError {
    ReservedAddressSpace(Address),
    AddressSpaceMismatch(Address, AddressSpace),
    InvalidRlp(DecoderError),
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
    Serialize,
    Deserialize,
)]
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

#[derive(
    Clone,
    Debug,
    RlpDecodable,
    RlpEncodable,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
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

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct CodeInfo {
    pub code: Arc<Bytes>,
    pub owner: Address,
}

impl CodeInfo {
    #[inline]
    pub fn code_size(&self) -> usize { self.code.len() }
}

impl Encodable for CodeInfo {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2).append(&*self.code).append(&self.owner);
    }
}

impl Decodable for CodeInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            code: Arc::new(rlp.val_at(0)?),
            owner: rlp.val_at(1)?,
        })
    }
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
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
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

#[derive(Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct Account {
    /// This field is not part of Account data, but kept for convenience. It
    /// should be rarely used except for debugging.
    address_local_info: Address,
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

/// Defined for Rlp serialization/deserialization.
#[derive(RlpEncodable, RlpDecodable)]
pub struct BasicAccount {
    pub balance: U256,
    pub nonce: U256,
    /// This is the number of tokens used in staking.
    pub staking_balance: U256,
    /// This is the number of tokens used as collateral for storage, which will
    /// be returned to balance if the storage is released.
    pub collateral_for_storage: U256,
    /// This is the accumulated interest return.
    pub accumulated_interest_return: U256,
}

/// Defined for Rlp serialization/deserialization.
#[derive(RlpEncodable, RlpDecodable)]
pub struct ContractAccount {
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
    pub fn address(&self) -> &Address { &self.address_local_info }

    pub fn set_address(
        &mut self, address: Address,
    ) -> Result<(), AccountError> {
        Self::check_address_space(&address)?;
        self.address_local_info = address;
        Ok(())
    }

    pub fn check_address_space(address: &Address) -> Result<(), AccountError> {
        if address.is_valid_address() {
            Ok(())
        } else {
            Err(AccountError::ReservedAddressSpace(*address))
        }
    }

    pub fn new_empty_with_balance(
        address: &Address, balance: &U256, nonce: &U256,
    ) -> Result<Account, AccountError> {
        Self::check_address_space(address)?;
        Ok(Self {
            address_local_info: *address,
            balance: *balance,
            nonce: *nonce,
            code_hash: KECCAK_EMPTY,
            staking_balance: 0.into(),
            collateral_for_storage: 0.into(),
            accumulated_interest_return: 0.into(),
            admin: Address::zero(),
            sponsor_info: Default::default(),
        })
    }

    fn from_basic_account(address: Address, a: BasicAccount) -> Self {
        Self {
            address_local_info: address,
            balance: a.balance,
            nonce: a.nonce,
            code_hash: KECCAK_EMPTY,
            staking_balance: a.staking_balance,
            collateral_for_storage: a.collateral_for_storage,
            accumulated_interest_return: a.accumulated_interest_return,
            admin: Address::zero(),
            sponsor_info: Default::default(),
        }
    }

    pub fn from_contract_account(
        address: Address, a: ContractAccount,
    ) -> Result<Self, AccountError> {
        if address.is_contract_address() {
            Ok(Self {
                address_local_info: address,
                balance: a.balance,
                nonce: a.nonce,
                code_hash: a.code_hash,
                staking_balance: a.staking_balance,
                collateral_for_storage: a.collateral_for_storage,
                accumulated_interest_return: a.accumulated_interest_return,
                admin: a.admin,
                sponsor_info: a.sponsor_info,
            })
        } else {
            Err(AccountError::AddressSpaceMismatch(
                address,
                AddressSpace::Contract,
            ))
        }
    }

    pub fn to_basic_account(&self) -> BasicAccount {
        BasicAccount {
            balance: self.balance,
            nonce: self.nonce,
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
        }
    }

    pub fn to_contract_account(&self) -> ContractAccount {
        ContractAccount {
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            staking_balance: self.staking_balance,
            collateral_for_storage: self.collateral_for_storage,
            accumulated_interest_return: self.accumulated_interest_return,
            admin: self.admin,
            sponsor_info: self.sponsor_info.clone(),
        }
    }

    pub fn new_from_rlp(
        address: Address, rlp: &Rlp,
    ) -> Result<Self, AccountError> {
        if address.is_contract_address() {
            Self::from_contract_account(address, ContractAccount::decode(rlp)?)
        } else if address.is_valid_address() {
            Ok(Self::from_basic_account(
                address,
                BasicAccount::decode(rlp)?,
            ))
        } else {
            Err(AccountError::ReservedAddressSpace(address))
        }
    }
}

impl Encodable for Account {
    fn rlp_append(&self, stream: &mut RlpStream) {
        if self.address_local_info.is_contract_address() {
            // A contract address can hold balance before its initialization
            // as a recipient of a simple transaction.
            // So we always determine how to serialize by the address type bits.
            stream.append_internal(&self.to_contract_account());
        } else if self.address_local_info.is_valid_address() {
            stream.append_internal(&self.to_basic_account());
        } else {
            unreachable!("other types of address are not supported yet.");
        }
    }
}

impl From<DecoderError> for AccountError {
    fn from(err: DecoderError) -> Self { AccountError::InvalidRlp(err) }
}

impl fmt::Display for AccountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            AccountError::ReservedAddressSpace(address) => {
                format!("Address space is reserved for {:?}", address)
            }
            AccountError::AddressSpaceMismatch(address, address_space) => {
                format!(
                    "Address {:?} not in address space {:?}",
                    address, address_space
                )
            }
            AccountError::InvalidRlp(err) => {
                format!("Transaction has invalid RLP structure: {}.", err)
            }
        };

        f.write_fmt(format_args!("Account error ({})", msg))
    }
}

impl std::error::Error for AccountError {
    fn description(&self) -> &str { "Account error" }
}
