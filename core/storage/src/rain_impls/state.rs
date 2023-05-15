use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{utils::access_mode::AccessMode, MptKeyValue};
use cfx_storage_primitives::rain::{
    StateRoot, StateRootAuxInfo, StateRootWithAuxInfo, StorageRoot,
};
use keccak_hash::keccak;
use parking_lot::{Mutex, RwLock};
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

use super::CACHE_DEPTH;
use crate::{
    convert_key, STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2,
    STORAGE_GET_TIMER, STORAGE_GET_TIMER2, STORAGE_SET_TIMER,
    STORAGE_SET_TIMER2,
};
use cfx_types::H256;
use kvdb::{DBKey, DBOp, DBTransaction, DBValue, KeyValueDB};
use metrics::{MeterTimer, ScopeTimer};
use parity_journaldb::DBHasher;
use patricia_trie_ethereum::RlpNodeCodec;
use profile::metric_record;
use rainblock_trie::MerklePatriciaTree;
use trie_db::NodeCodec;

pub struct State {
    pub(crate) read_only: bool,

    pub(crate) state: Arc<Mutex<MerklePatriciaTree<CACHE_DEPTH>>>,
    pub(crate) epoch_root: H256,
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        metric_record!(STORAGE_GET_TIMER, STORAGE_GET_TIMER2);

        Ok(self
            .state
            .lock()
            .get(convert_key(access_key).as_ref().to_vec())
            .map(Into::into))
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        assert!(!self.read_only);
        trace!("MPTStateOp: Set key {:?}, value {:?}", access_key, value);
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);

        self.state
            .lock()
            .put(convert_key(access_key).as_ref().to_vec(), value.into());
        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        unimplemented!()
    }

    fn delete_test_only(
        &mut self, access_key: StorageKey,
    ) -> crate::Result<Option<Box<[u8]>>> {
        unreachable!()
    }

    fn delete_all<AM: AccessMode>(
        &mut self, access_key_prefix: StorageKey,
    ) -> crate::Result<Option<Vec<MptKeyValue>>> {
        warn!(
            "MPTState: No op for delete all. read only: {}, : key:{:?}",
            AM::is_read_only(),
            access_key_prefix
        );
        Ok(None)
    }

    fn compute_state_root(&mut self) -> crate::Result<StateRootWithAuxInfo> {
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);
        assert!(!self.read_only);
        self.epoch_root = self
            .state
            .lock()
            .root()
            .unwrap_or(RlpNodeCodec::<DBHasher>::hashed_null_node());
        self.get_state_root()
    }

    fn get_state_root(&self) -> crate::Result<StateRootWithAuxInfo> {
        Ok(StateRootWithAuxInfo {
            state_root: StateRoot(self.epoch_root),
            aux_info: StateRootAuxInfo {
                state_root_hash: self.epoch_root,
            },
        })
    }

    fn commit(
        &mut self, epoch: EpochId,
    ) -> crate::Result<StateRootWithAuxInfo> {
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);

        self.epoch_root = self.state.lock().commit()?;
        self.get_state_root()
    }
}

impl StateTraitExt for State {
    fn get_with_proof(
        &self, access_key: StorageKey,
    ) -> crate::Result<(Option<Box<[u8]>>, StateProof)> {
        unimplemented!()
    }

    fn get_node_merkle_all_versions<WithProof: StaticBool>(
        &self, access_key: StorageKey,
    ) -> crate::Result<(StorageRoot, StorageRootProof)> {
        unimplemented!()
    }
}
