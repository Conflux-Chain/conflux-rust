// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    storage::{
        Error as StorageError, ErrorKind as StorageErrorKind, StateProof,
        StateRootWithAuxInfo, Storage, StorageKey, StorageTrait,
    },
};
use cfx_types::{Address, H256};
use primitives::{Account, EpochId};

mod error;

pub use self::error::{Error, ErrorKind, Result};

pub struct StateDb<'a> {
    storage: Storage<'a>,
}

impl<'a> StateDb<'a> {
    pub fn new(storage: Storage<'a>) -> Self { StateDb { storage } }

    #[allow(unused)]
    pub fn get_storage_mut(&mut self) -> &mut Storage<'a> { &mut self.storage }

    pub fn get<T>(&self, key: StorageKey) -> Result<Option<T>>
    where T: ::rlp::Decodable {
        let raw = match self.storage.get(key) {
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
        match self.get_raw(StorageKey::new_code_key(address, code_hash)) {
            Ok(Some(code)) => Some(code.to_vec()),
            _ => {
                warn!("Failed reverse get of {}", code_hash);
                None
            }
        }
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = StorageKey::new_account_key(address);
        let raw = match self.storage.get(key) {
            Ok(maybe_value) => match maybe_value {
                None => return Ok(None),
                Some(raw) => raw,
            },
            Err(e) => {
                return Err(e.into());
            }
        };
        //        println!("get key={:?} value={:?}", key, raw);

        let account = Account::new_from_rlp(address, raw.as_ref())?;
        Ok(Some(account))
    }

    pub fn get_raw(&self, key: StorageKey) -> Result<Option<Box<[u8]>>> {
        let r = Ok(self.storage.get(key)?);
        trace!("get_raw key={:?}, value={:?}", key, r);
        r
    }

    pub fn get_raw_with_proof(
        &self, key: StorageKey,
    ) -> Result<(Option<Box<[u8]>>, StateProof)> {
        let r = Ok(self.storage.get_with_proof(key)?);
        trace!("get_raw_with_proof key={:?}, value={:?}", key, r);
        r
    }

    pub fn set<T>(&mut self, key: StorageKey, value: &T) -> Result<()>
    where T: ::rlp::Encodable {
        trace!("set key={:?} value={:?}", key, ::rlp::encode(value));
        self.set_raw(key, ::rlp::encode(value).into_boxed_slice())
    }

    pub fn set_raw(&mut self, key: StorageKey, value: Box<[u8]>) -> Result<()> {
        match self.storage.set(key, value) {
            Ok(_) => Ok(()),
            Err(StorageError(StorageErrorKind::MPTKeyNotFound, _)) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete(&mut self, key: StorageKey) -> Result<()> {
        match self.storage.delete(key) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_all(
        &mut self, key_prefix: StorageKey,
    ) -> Result<Option<Vec<(Vec<u8>, Box<[u8]>)>>> {
        Ok(self.storage.delete_all(key_prefix)?)
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
