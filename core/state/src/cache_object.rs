// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait CachedObject: Encodable + Sized {
    type HashKeyType: AsStorageKey;

    fn load_from_rlp(key: &Self::HashKeyType, rlp: &Rlp) -> Result<Self>;

    fn load<StateDb: StateDbOps>(
        key: &Self::HashKeyType, db: &StateDb,
    ) -> Result<Option<Self>> {
        let storage_key = key.storage_key();
        match db.get_raw(storage_key) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(v)) => Ok(Some(Self::load_from_rlp(key, &Rlp::new(&v))?)),
        }
    }

    fn update<StateDbStorage: StorageStateTrait>(
        &self, key: &Self::HashKeyType,
        db: &mut StateDbGeneric<StateDbStorage>,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        db.set_raw(
            key.storage_key(),
            self.rlp_bytes().into_boxed_slice(),
            debug_record,
        )
    }

    fn delete<StateDbStorage: StorageStateTrait>(
        &self, key: &Self::HashKeyType,
        db: &mut StateDbGeneric<StateDbStorage>,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> Result<()>
    {
        db.delete(key.storage_key(), debug_record)
    }
}

/// Accound address and code hash.
#[allow(unused)]
pub struct CodeAddress(Address, H256);

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

impl CachedObject for CachedAccount {
    type HashKeyType = Address;

    fn load_from_rlp(key: &Address, rlp: &Rlp) -> Result<Self> {
        Ok(Self {
            object: Account::new_from_rlp(key.clone(), rlp)?,
        })
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

use crate::StateDbOps;
use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::{Result, StateDbGeneric};
use cfx_storage::StorageStateTrait;
use cfx_types::{Address, H256};
use primitives::{Account, StorageKey};
use rlp::{Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};
