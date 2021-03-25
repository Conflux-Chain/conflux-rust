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

    fn update<StateDb: StateDbOps>(
        &self, key: &Self::HashKeyType, db: &mut StateDb,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        db.set(key.storage_key(), self, debug_record)
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

pub struct CachedAccount {
    object: Account,
}

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

use crate::StateDbOps;
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::Result;
use cfx_types::{Address, H256};
use primitives::{is_default::IsDefault, Account, CodeInfo, StorageKey};
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};
