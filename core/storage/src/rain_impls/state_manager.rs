use super::{
    config::storage_manager::StorageConfiguration, state::State,
    state_index::StateIndex, state_trait::StateManagerTrait,
};
use crate::{KvdbRocksdb, Result, SnapshotInfo};
use cfx_internal_common::{
    consensus_api::StateMaintenanceTrait, StateAvailabilityBoundary,
};
use cfx_storage_primitives::rain::StateRootWithAuxInfo;
use cfx_types::H256;
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_rocksdb::{CompactionProfile, Database, DatabaseConfig};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use parity_journaldb::DBHasher;
use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use patricia_trie_ethereum::RlpNodeCodec;
use primitives::{EpochId, MerkleHash};
use rainblock_trie::MerklePatriciaTree;
use std::{path::Path, sync::Arc};
use trie_db::NodeCodec;

use super::CACHE_DEPTH;

// #[derive(MallocSizeOfDerive)]
pub struct StateManager {
    snapshot_epoch_count: u32,
    db: Arc<Mutex<MerklePatriciaTree<CACHE_DEPTH>>>,
}

unsafe impl Send for StateManager {}
unsafe impl Sync for StateManager {}

impl MallocSizeOf for StateManager {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        return 0;
        todo!()
    }
}

fn open_backend(db_dir: &str) -> Arc<Database> {
    let mut db_config = DatabaseConfig::with_columns(3);

    db_config.memory_budget = Some(4096);
    db_config.compaction = CompactionProfile::auto(Path::new(db_dir));
    db_config.disable_wal = false;

    let db = Database::open(&db_config, db_dir).unwrap();

    Arc::new(db)
}

impl StateManager {
    pub fn get_storage_manager(&self) -> &StateManager { &*self }

    pub fn new(conf: StorageConfiguration) -> Result<Self> {
        let backend: Arc<dyn KeyValueDB> =
            open_backend(conf.path_storage_dir.to_str().unwrap());

        let db = Arc::new(Mutex::new(MerklePatriciaTree::new(backend)));
        Ok(Self {
            snapshot_epoch_count: conf.snapshot_epoch_count,
            db,
        })
    }

    pub fn get_snapshot_epoch_count(&self) -> u32 { self.snapshot_epoch_count }

    pub fn maintain_state_confirmed<ConsensusInner: StateMaintenanceTrait>(
        &self, consensus_inner: &ConsensusInner, stable_checkpoint_height: u64,
        era_epoch_count: u64, confirmed_height: u64,
        state_availability_boundary: &RwLock<StateAvailabilityBoundary>,
    ) -> Result<()>
    {
        Ok(())
    }

    pub fn get_snapshot_info_at_epoch(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<SnapshotInfo> {
        todo!()
    }

    pub fn log_usage(&self) {}
}

impl StateManagerTrait for StateManager {
    fn get_state_no_commit(
        self: &Arc<Self>, epoch_id: StateIndex, try_open: bool,
    ) -> Result<Option<State>> {
        assert!(epoch_id.is_read_only());
        let root = epoch_id.state_root.state_root.0.clone();
        Ok(Some(self.new_state(true, 0, root)))
    }

    fn get_state_for_next_epoch(
        self: &Arc<Self>, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>> {
        let epoch = if let Some(height) = parent_epoch_id.height {
            height + 1
        } else {
            0
        };

        let root = parent_epoch_id.state_root.state_root.0.clone();

        Ok(Some(
            if parent_epoch_id.is_read_only() {
                self.new_state(true, epoch, root)
            } else {
                self.new_state(false, epoch, root)
            },
        ))
    }

    fn get_state_for_genesis_write(self: &Arc<Self>) -> State {
        self.new_state(false, 0, RlpNodeCodec::<DBHasher>::hashed_null_node())
    }
}

impl StateManager {
    fn new_state(&self, read_only: bool, epoch: u64, root: H256) -> State {
        State {
            read_only,
            state: self.db.clone(),
            epoch_root: root,
        }
    }
}
