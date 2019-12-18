// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bytes::Bytes,
    executive::STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    parameters::consensus_internal::INITIAL_INTEREST_RATE,
    storage::{
        Error as StorageError, ErrorKind as StorageErrorKind, StateProof,
        StateRootWithAuxInfo, Storage, StorageTrait,
    },
};
use cfx_types::{Address, H256, U256};
use primitives::{Account, EpochId, StorageKey};

mod error;

pub use self::error::{Error, ErrorKind, Result};

pub struct StateDb<'a> {
    storage: Storage<'a>,
}

impl<'a> StateDb<'a> {
    const ACCUMULATE_INTEREST_RATE_KEY: &'static [u8] =
        b"accumulate_interest_rate";
    const INTEREST_RATE_KEY: &'static [u8] = b"interest_rate";
    const TOTAL_BANK_TOKENS_KEY: &'static [u8] = b"total_bank_tokens";
    const TOTAL_STORAGE_TOKENS_KEY: &'static [u8] = b"total_storage_tokens";
    const TOTAL_TOKENS_KEY: &'static [u8] = b"total_tokens";

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
        self.get::<Account>(StorageKey::new_account_key(address))
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

    pub fn get_interest_rate(&self) -> Result<U256> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::INTEREST_RATE_KEY,
        );
        let interest_rate_opt = self.get::<U256>(interest_rate_key)?;
        // This number is 0.04 * INTEREST_RATE_SCALE
        Ok(interest_rate_opt.unwrap_or(U256::from(INITIAL_INTEREST_RATE)))
    }

    pub fn get_accumulate_interest_rate(&self) -> Result<U256> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::ACCUMULATE_INTEREST_RATE_KEY,
        );
        let acc_interest_rate_opt = self.get::<U256>(acc_interest_rate_key)?;
        Ok(acc_interest_rate_opt.unwrap_or(U256::zero()))
    }

    pub fn get_total_tokens(&self) -> Result<U256> {
        let total_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_TOKENS_KEY,
        );
        let total_tokens_opt = self.get::<U256>(total_tokens_key)?;
        Ok(total_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn get_total_bank_tokens(&self) -> Result<U256> {
        let total_bank_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_BANK_TOKENS_KEY,
        );
        let total_bank_tokens_opt = self.get::<U256>(total_bank_tokens_key)?;
        Ok(total_bank_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn get_total_storage_tokens(&self) -> Result<U256> {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_STORAGE_TOKENS_KEY,
        );
        let total_storage_tokens_opt =
            self.get::<U256>(total_storage_tokens_key)?;
        Ok(total_storage_tokens_opt.unwrap_or(U256::zero()))
    }

    pub fn set_interest_rate(&mut self, interest_rate: &U256) -> Result<()> {
        let interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::INTEREST_RATE_KEY,
        );
        self.set::<U256>(interest_rate_key, interest_rate)
    }

    pub fn set_accumulate_interest_rate(
        &mut self, accumulate_interest_rate: &U256,
    ) -> Result<()> {
        let acc_interest_rate_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::ACCUMULATE_INTEREST_RATE_KEY,
        );
        self.set::<U256>(acc_interest_rate_key, accumulate_interest_rate)
    }

    pub fn set_total_tokens(&mut self, total_tokens: &U256) -> Result<()> {
        let total_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_TOKENS_KEY,
        );
        self.set::<U256>(total_tokens_key, total_tokens)
    }

    pub fn set_total_bank_tokens(
        &mut self, total_bank_tokens: &U256,
    ) -> Result<()> {
        let total_bank_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_BANK_TOKENS_KEY,
        );
        self.set::<U256>(total_bank_tokens_key, total_bank_tokens)
    }

    pub fn set_total_storage_tokens(
        &mut self, total_storage_tokens: &U256,
    ) -> Result<()> {
        let total_storage_tokens_key = StorageKey::new_storage_key(
            &STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
            Self::TOTAL_STORAGE_TOKENS_KEY,
        );
        self.set::<U256>(total_storage_tokens_key, total_storage_tokens)
    }
}
