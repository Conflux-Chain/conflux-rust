// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::KECCAK_EMPTY,
    storage::{
        Error as StorageError, ErrorKind as StorageErrorKind, MerkleHash,
        Storage, StorageTrait,
    },
};
use cfx_types::Address;
use primitives::{Account, EpochId};

mod error;
mod storage_key;

pub use self::{
    error::{Error, ErrorKind, Result},
    storage_key::StorageKey,
};

pub struct StateDb<'a> {
    storage: Storage<'a>,
}

impl<'a> StateDb<'a> {
    pub fn new(storage: Storage<'a>) -> Self { StateDb { storage } }

    pub fn get<T>(&self, key: &StorageKey) -> Result<Option<T>>
    where T: ::rlp::Decodable {
        let raw = match self.storage.get(key.as_ref()) {
            Ok(maybe_value) => match maybe_value {
                None => return Ok(None),
                Some(raw) => raw,
            },
            Err(e) => {
                return Err(e.into());
            }
        };
        //        println!("get key={:?} value={:?}", key, raw);
        Ok(Some(::rlp::decode::<T>(raw.as_ref())?))
    }

    pub fn get_account(
        &self, address: &Address, with_storage_root: bool,
    ) -> Result<Option<Account>> {
        let key = StorageKey::new_account_key(address);
        let raw = match self.storage.get(key.as_ref()) {
            Ok(maybe_value) => match maybe_value {
                None => return Ok(None),
                Some(raw) => raw,
            },
            Err(e) => {
                return Err(e.into());
            }
        };
        //        println!("get key={:?} value={:?}", key, raw);
        let storage_root;
        if with_storage_root {
            let storage_root_key = StorageKey::new_storage_root_key(address);
            storage_root = self
                .storage
                .get_merkle_hash(storage_root_key.as_ref())?
                .unwrap();
        } else {
            storage_root = KECCAK_EMPTY;
        }
        let account =
            Account::new_from_rlp(address, raw.as_ref(), &storage_root)?;
        Ok(Some(account))
    }

    pub fn get_raw(&self, key: &StorageKey) -> Result<Option<Box<[u8]>>> {
        let r = Ok(self.storage.get(key.as_ref())?);
        trace!("get_raw key={:?}, value={:?}", key.as_ref(), r);
        r
    }

    pub fn set<T>(&mut self, key: &StorageKey, value: &T) -> Result<()>
    where T: ::rlp::Encodable {
        trace!(
            "set key={:?} value={:?}",
            key.as_ref(),
            ::rlp::encode(value)
        );
        self.set_raw(key, &::rlp::encode(value))
    }

    pub fn set_raw(&mut self, key: &StorageKey, value: &[u8]) -> Result<()> {
        match self.storage.set(key.as_ref(), value) {
            Ok(_) => Ok(()),
            Err(StorageError(StorageErrorKind::MPTKeyNotFound, _)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(&mut self, key: &StorageKey) -> Result<()> {
        match self.storage.delete(key.as_ref()) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_all(
        &mut self, key_prefix: &StorageKey,
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>> {
        Ok(self.storage.delete_all(key_prefix.as_ref())?)
    }

    pub fn commit(&mut self, epoch_id: EpochId) -> Result<MerkleHash> {
        let merkle_hash = self.storage.compute_state_root()?;
        self.storage.commit(epoch_id)?;

        Ok(merkle_hash)
    }
}
