// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait CachedObject: Encodable + IsDefault + Sized {
    type HashKeyType: AsStorageKey;

    fn load_from_rlp(key: &Self::HashKeyType, rlp: &Rlp) -> Result<Self>;

    fn load<StateDb: StateDbOps>(
        key: &Self::HashKeyType, db: &StateDb,
    ) -> Result<Option<Self>> {
        match db.get_raw(key.storage_key()) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(v)) => Ok(Some(Self::load_from_rlp(key, &Rlp::new(&v))?)),
        }
    }

    // This method also checks if the value IsDefault, if so map the update to a
    // deletion.
    fn update<StateDb: StateDbOps>(
        &self, key: &Self::HashKeyType, db: &mut StateDb,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        if self.is_default() {
            db.delete(key.storage_key(), debug_record)
        } else {
            db.set(key.storage_key(), self, debug_record)
        }
    }

    fn delete<StateDb: StateDbOps>(
        key: &Self::HashKeyType, db: &mut StateDb,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        db.delete(key.storage_key(), debug_record)
    }
}

/// Account address and code hash.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CodeAddress(pub Address, pub H256);

/// Contract address and user address.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CommissionPrivilegeAddress(pub Vec<u8>);

impl CommissionPrivilegeAddress {
    pub fn new(
        contract_address: Address, user_address: Address,
    ) -> CommissionPrivilegeAddress {
        let mut key = Vec::with_capacity(Address::len_bytes() * 2);
        key.extend_from_slice(contract_address.as_ref());
        key.extend_from_slice(user_address.as_ref());
        CommissionPrivilegeAddress(key)
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DepositListAddress(pub Address);

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct VoteStakeListAddress(pub Address);

pub struct CachedAccount {
    object: Account,
}

impl CachedAccount {
    pub fn new_basic(
        address: &Address, balance: &U256, nonce: &U256,
    ) -> Result<Self> {
        Ok(Self {
            object: Account::new_empty_with_balance(address, balance, nonce)?,
        })
    }
}

pub struct CachedCommissionPrivilege {
    has_privilege: bool,
}

impl CachedCommissionPrivilege {
    pub fn new(has_privilege: bool) -> CachedCommissionPrivilege {
        CachedCommissionPrivilege { has_privilege }
    }

    pub fn has_privilege(&self) -> bool { self.has_privilege }

    pub fn add_privilege(&mut self) { self.has_privilege = true; }

    pub fn remove_privilege(&mut self) { self.has_privilege = false; }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct StorageAddress(pub Address, pub Vec<u8>);

pub trait ToHashKey<K> {
    fn to_hash_key(&self) -> K;
}

pub trait AsStorageKey {
    fn storage_key(&self) -> StorageKey;
}

impl AsStorageKey for Address {
    fn storage_key(&self) -> StorageKey {
        StorageKey::AccountKey(self.0.as_ref())
    }
}

impl ToHashKey<Address> for Address {
    fn to_hash_key(&self) -> Self { self.clone() }
}

impl AsStorageKey for CodeAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::CodeKey {
            address_bytes: self.0.as_ref(),
            code_hash_bytes: self.1.as_ref(),
        }
    }
}

impl ToHashKey<CodeAddress> for CodeAddress {
    fn to_hash_key(&self) -> CodeAddress { self.clone() }
}

impl AsStorageKey for CommissionPrivilegeAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::StorageKey {
            address_bytes: SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS.as_ref(),
            storage_key: self.0.as_ref(),
        }
    }
}

impl ToHashKey<CommissionPrivilegeAddress> for CommissionPrivilegeAddress {
    fn to_hash_key(&self) -> Self { self.clone() }
}

impl AsStorageKey for DepositListAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::DepositListKey(self.0.as_ref())
    }
}

impl ToHashKey<DepositListAddress> for DepositListAddress {
    fn to_hash_key(&self) -> Self { self.clone() }
}

impl AsStorageKey for VoteStakeListAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::VoteListKey(self.0.as_ref())
    }
}

impl ToHashKey<VoteStakeListAddress> for VoteStakeListAddress {
    fn to_hash_key(&self) -> Self { self.clone() }
}

impl AsStorageKey for StorageAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::StorageKey {
            address_bytes: self.0.as_ref(),
            storage_key: self.1.as_ref(),
        }
    }
}

impl ToHashKey<StorageAddress> for StorageAddress {
    fn to_hash_key(&self) -> Self { self.clone() }
}

impl CachedObject for CachedAccount {
    type HashKeyType = Address;

    fn load_from_rlp(key: &Address, rlp: &Rlp) -> Result<Self> {
        Ok(Self {
            object: Account::new_from_rlp(key.clone(), rlp)?,
        })
    }
}

impl CachedObject for CodeInfo {
    type HashKeyType = CodeAddress;

    fn load_from_rlp(_key: &CodeAddress, rlp: &Rlp) -> Result<Self> {
        Ok(Self::decode(rlp)?)
    }
}

impl CachedObject for CachedCommissionPrivilege {
    type HashKeyType = CommissionPrivilegeAddress;

    fn load_from_rlp(
        _key: &CommissionPrivilegeAddress, rlp: &Rlp,
    ) -> Result<Self> {
        Ok(Self {
            has_privilege: bool::decode(rlp)?,
        })
    }
}

impl CachedObject for DepositList {
    type HashKeyType = DepositListAddress;

    fn load_from_rlp(_key: &DepositListAddress, rlp: &Rlp) -> Result<Self> {
        Ok(Self::decode(rlp)?)
    }
}

impl CachedObject for VoteStakeList {
    type HashKeyType = VoteStakeListAddress;

    fn load_from_rlp(_key: &VoteStakeListAddress, rlp: &Rlp) -> Result<Self> {
        Ok(Self::decode(rlp)?)
    }
}

impl CachedObject for StorageValue {
    type HashKeyType = StorageAddress;

    fn load_from_rlp(_key: &StorageAddress, rlp: &Rlp) -> Result<Self> {
        Ok(Self::decode(rlp)?)
    }
}

impl Deref for CachedAccount {
    type Target = Account;

    fn deref(&self) -> &Self::Target { &self.object }
}

impl DerefMut for CachedAccount {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.object }
}

impl Encodable for CachedAccount {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_internal(&self.object); }
}

impl IsDefault for CachedAccount {
    fn is_default(&self) -> bool { self.object.is_default() }
}

impl Deref for CachedCommissionPrivilege {
    type Target = bool;

    fn deref(&self) -> &Self::Target { &self.has_privilege }
}

impl DerefMut for CachedCommissionPrivilege {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.has_privilege }
}

impl Encodable for CachedCommissionPrivilege {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&self.has_privilege);
    }
}

impl IsDefault for CachedCommissionPrivilege {
    fn is_default(&self) -> bool { self.has_privilege.is_default() }
}

use crate::StateDbOps;
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::Result;
use cfx_types::{Address, H256, U256};
use primitives::{
    is_default::IsDefault, Account, CodeInfo, DepositList, StorageKey,
    StorageValue, VoteStakeList,
};
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

use cfx_parameters::internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS;
