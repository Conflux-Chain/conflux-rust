// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    storage::{
        Error as StorageError, ErrorKind as StorageErrorKind, StateProof,
        Storage, StorageTrait,
    },
};
use cfx_types::{Address, H256};
use primitives::{Account, EpochId, StateRootWithAuxInfo};

mod error;
mod storage_key;

pub use self::{
    error::{Error, ErrorKind, Result},
    storage_key::{KeyPadding, StorageKey},
};

pub struct StateDb<'a> {
    storage: Storage<'a>,
}

impl<'a> StateDb<'a> {
    pub fn new(storage: Storage<'a>) -> Self { StateDb { storage } }

    #[allow(unused)]
    pub fn get_storage_mut(&mut self) -> &mut Storage<'a> { &mut self.storage }

    pub fn account_key(&self, address: &Address) -> StorageKey {
        StorageKey::new_account_key(address, self.storage.get_padding())
    }

    pub fn code_root_key(&self, address: &Address) -> StorageKey {
        StorageKey::new_code_root_key(address, self.storage.get_padding())
    }

    pub fn code_key(&self, address: &Address, code_hash: &H256) -> StorageKey {
        StorageKey::new_code_key(address, code_hash, self.storage.get_padding())
    }

    pub fn storage_root_key(&self, address: &Address) -> StorageKey {
        StorageKey::new_storage_root_key(address, self.storage.get_padding())
    }

    pub fn storage_key(&self, address: &Address, key: &[u8]) -> StorageKey {
        StorageKey::new_storage_key(address, key, self.storage.get_padding())
    }

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

    pub fn get_code(
        &self, address: &Address, code_hash: &H256,
    ) -> Option<Bytes> {
        match self.get_raw(&self.code_key(address, code_hash)) {
            Ok(Some(code)) => Some(code.to_vec()),
            _ => {
                warn!("Failed reverse get of {}", code_hash);
                None
            }
        }
    }

    // TODO: check if we need storage root, if so, implement.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = self.account_key(address);
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

        // TODO: check if we need storage root.
        // The commented out code below demonstrates how to obtain
        // the storage root in Delta MPT.
        /*
        let storage_root;
        if with_storage_root {
            let storage_root_key = StorageKey::new_storage_root_key(
                address,
                self.storage.get_padding(),
            );
            storage_root = self
                .storage
                .get_merkle_hash(storage_root_key.as_ref())?
                .unwrap();
        } else {
            storage_root = KECCAK_EMPTY;
        }
        */
        let account = Account::new_from_rlp(address, raw.as_ref())?;
        Ok(Some(account))
    }

    pub fn get_raw(&self, key: &StorageKey) -> Result<Option<Box<[u8]>>> {
        let r = Ok(self.storage.get(key.as_ref())?);
        trace!("get_raw key={:?}, value={:?}", key.as_ref(), r);
        r
    }

    pub fn get_raw_with_proof(
        &self, key: &Vec<u8>,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        let r = Ok(self.storage.get_with_proof(key)?);
        trace!("get_raw_with_proof key={:?}, value={:?}", key, r);
        r
    }

    pub fn set<T>(&mut self, key: &StorageKey, value: &T) -> Result<()>
    where T: ::rlp::Encodable {
        trace!(
            "set key={:?} value={:?}",
            key.as_ref(),
            ::rlp::encode(value)
        );
        self.set_raw(key, ::rlp::encode(value).into_boxed_slice())
    }

    pub fn set_raw(
        &mut self, key: &StorageKey, value: Box<[u8]>,
    ) -> Result<()> {
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

    /// This method is only used for genesis block because state root is
    /// required to compute genesis epoch_id. For other blocks there are
    /// deferred execution so the state root computation is merged inside
    /// commit method.
    pub fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo> {
        Ok(self.storage.compute_state_root()?)
    }

    pub fn commit(
        &mut self, epoch_id: EpochId,
    ) -> Result<StateRootWithAuxInfo> {
        let result = self.compute_state_root();
        self.storage.commit(epoch_id)?;

        result
    }
}
