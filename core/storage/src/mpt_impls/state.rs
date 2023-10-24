use super::{
    proof_type::{StateProof, StorageRootProof},
    state_manager::StateManager,
    state_trait::{StateTrait, StateTraitExt},
    state_trees::StateTrees,
};
use crate::{convert_key, utils::access_mode::AccessMode, MptKeyValue};
use cfx_storage_primitives::mpt::{
    StateRoot, StateRootAuxInfo, StateRootWithAuxInfo, StorageRoot,
};
use keccak_hash::{keccak, H256};
use parity_journaldb::{DBHasher, JournalDB};
use parking_lot::RwLock;
use primitives::{EpochId, StaticBool, StorageKey};
use std::sync::Arc;

use crate::{
    STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2, STORAGE_GET_TIMER,
    STORAGE_GET_TIMER2, STORAGE_SET_TIMER, STORAGE_SET_TIMER2,
};
use kvdb::DBTransaction;
use metrics::{MeterTimer, ScopeTimer};
use patricia_trie_ethereum::RlpNodeCodec;
use profile::metric_record;
use trie_db::{Trie, TrieMut};

pub type TrieDBMut<'db> =
    trie_db::TrieDBMut<'db, DBHasher, RlpNodeCodec<DBHasher>>;
pub type TrieDB<'db> = trie_db::TrieDB<'db, DBHasher, RlpNodeCodec<DBHasher>>;

pub struct State {
    pub(crate) read_only: bool,

    pub(crate) state: Arc<RwLock<Box<dyn JournalDB>>>,
    pub(crate) root: H256,
    pub(crate) epoch: u64,
}

impl StateTrait for State {
    fn get(&self, access_key: StorageKey) -> crate::Result<Option<Box<[u8]>>> {
        metric_record!(STORAGE_GET_TIMER, STORAGE_GET_TIMER2);

        let db = self.state.read();
        let hash_db = &db.as_hash_db();

        let trie = TrieDB::new(hash_db, &self.root).unwrap();
        Ok(trie
            .get(convert_key(access_key).as_ref())
            .unwrap()
            .map(|x| x.into_vec().into_boxed_slice()))
    }

    fn set(
        &mut self, access_key: StorageKey, value: Box<[u8]>,
    ) -> crate::Result<()> {
        assert!(!self.read_only);
        trace!("MPTStateOp: Set key {:?}, value {:?}", access_key, value);
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);

        let mut db = self.state.write();
        let hash_db = db.as_hash_db_mut();

        let mut trie =
            TrieDBMut::from_existing(hash_db, &mut self.root).unwrap();
        trie.insert(convert_key(access_key).as_ref(), value.as_ref())
            .unwrap();
        Ok(())
    }

    fn delete(&mut self, access_key: StorageKey) -> crate::Result<()> {
        assert!(!self.read_only);
        trace!("MPTStateOp: Del key {:?}", access_key);
        metric_record!(STORAGE_SET_TIMER, STORAGE_SET_TIMER2);

        let mut db = self.state.write();
        let hash_db = db.as_hash_db_mut();

        let mut trie =
            TrieDBMut::from_existing(hash_db, &mut self.root).unwrap();

        trie.remove(convert_key(access_key).as_ref()).unwrap();

        Ok(())
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
        assert!(!self.read_only);
        self.get_state_root()
    }

    fn get_state_root(&self) -> crate::Result<StateRootWithAuxInfo> {
        Ok(StateRootWithAuxInfo {
            state_root: StateRoot(self.root),
            aux_info: StateRootAuxInfo {
                state_root_hash: self.root,
            },
        })
    }

    fn commit(
        &mut self, epoch: EpochId,
    ) -> crate::Result<StateRootWithAuxInfo> {
        metric_record!(STORAGE_COMMIT_TIMER, STORAGE_COMMIT_TIMER2);

        let mut batch = DBTransaction::new();
        let mut db = self.state.write();

        db.journal_under(&mut batch, self.epoch, &epoch).unwrap();
        db.backing().write(batch).unwrap();
        db.flush();
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
