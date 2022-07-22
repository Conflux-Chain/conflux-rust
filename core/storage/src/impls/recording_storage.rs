// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// `RecordingStorage` is a wrapper around other storage implementations that
// tracks all read accesses. It can then be turned into a `StateProof` that is
// able to prove all key-value accesses.

pub struct RecordingStorage<Storage: StateTrait> {
    storage: Storage,

    // note: we need interior mutability so that we can record accesses and we
    // need to use Mutex for this as State implementations need to be Send and
    // Sync. However, the current execution logic is single-threaded.
    proof_merger: Mutex<StateProofMerger>,
}

impl<Storage: StateTrait> RecordingStorage<Storage> {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            proof_merger: Default::default(),
        }
    }

    pub fn try_into_proof(self) -> Result<StateProof> {
        self.proof_merger.into_inner().finish()
    }
}

impl<Storage: StateTrait + StateTraitExt> RecordingStorage<Storage> {
    fn record_kvs(&self, kvs: &Vec<MptKeyValue>) -> Result<()> {
        let mut proof_merger = self.proof_merger.lock();

        for (k, _) in kvs {
            let access_key =
                StorageKeyWithSpace::from_key_bytes::<CheckInput>(k)?;
            let (_, proof) = self.storage.get_with_proof(access_key)?;
            proof_merger.merge(proof);
        }

        Ok(())
    }
}

impl<Storage: StateTrait + StateTraitExt> StateTrait
    for RecordingStorage<Storage>
{
    delegate! {
        to self.storage {
            fn set(&mut self, access_key: StorageKeyWithSpace, value: Box<[u8]>) -> Result<()>;
            fn delete(&mut self, access_key: StorageKeyWithSpace) -> Result<()>;
            fn delete_test_only(&mut self, access_key: StorageKeyWithSpace) -> Result<Option<Box<[u8]>>>;
            fn compute_state_root(&mut self) -> Result<StateRootWithAuxInfo>;
            fn get_state_root(&self) -> Result<StateRootWithAuxInfo>;
            fn commit(&mut self, epoch_id: EpochId) -> Result<StateRootWithAuxInfo>;
        }
    }

    // we need to record `get` operations
    fn get(
        &self, access_key: StorageKeyWithSpace,
    ) -> Result<Option<Box<[u8]>>> {
        let (val, proof) = self.storage.get_with_proof(access_key)?;
        self.proof_merger.lock().merge(proof);
        Ok(val)
    }

    fn delete_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        match self.storage.delete_all(access_key_prefix)? {
            None => Ok(None),
            Some(kvs) => {
                self.record_kvs(&kvs)?;
                Ok(Some(kvs))
            }
        }
    }

    fn read_all(
        &mut self, access_key_prefix: StorageKeyWithSpace,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        match self.storage.read_all(access_key_prefix)? {
            None => Ok(None),
            Some(kvs) => {
                self.record_kvs(&kvs)?;
                Ok(Some(kvs))
            }
        }
    }
}

use crate::{
    impls::{
        errors::*, merkle_patricia_trie::MptKeyValue, state_proof::StateProof,
    },
    state::*,
    StateProofMerger,
};
use cfx_internal_common::StateRootWithAuxInfo;
use delegate::delegate;
use parking_lot::Mutex;
use primitives::{CheckInput, EpochId, StorageKeyWithSpace};
