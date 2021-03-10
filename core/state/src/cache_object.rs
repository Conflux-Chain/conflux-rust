// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

trait AsStorageKey {
    fn storage_key(&self) -> StorageKey;
}

trait CachedObject: Encodable + Sized {
    type HashKeyType: AsStorageKey;

    fn load_from_rlp(key: &Self::HashKeyType, rlp: &Rlp) -> Result<Self>;

    fn load<StateDbStorage: StorageStateTrait>(
        key: &Self::HashKeyType, db: &StateDbGeneric<StateDbStorage>,
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

#[derive(Eq, PartialEq, Hash)]
pub struct AccountAddress(Address);
/// Accound address and code hash.
#[allow(unused)]
pub struct CodeAddress(Address, H256);

pub struct CachedAccount {
    object: Account,
}

impl AsStorageKey for AccountAddress {
    fn storage_key(&self) -> StorageKey {
        StorageKey::AccountKey(self.0.as_ref())
    }
}

impl CachedObject for CachedAccount {
    type HashKeyType = AccountAddress;

    fn load_from_rlp(key: &AccountAddress, rlp: &Rlp) -> Result<Self> {
        Ok(Self {
            object: Account::new_from_rlp(key.0, rlp)?,
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

impl Borrow<Address> for AccountAddress {
    fn borrow(&self) -> &Address { &self.0 }
}

impl Encodable for CachedAccount {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_internal(&self.object); }
}

use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::{Result, StateDbGeneric};
use cfx_storage::StorageStateTrait;
use cfx_types::{Address, H256};
use primitives::{Account, StorageKey};
use rlp::{Encodable, Rlp, RlpStream};
use std::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
};
