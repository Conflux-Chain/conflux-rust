// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: Reason about their safety.
#![allow(clippy::mut_from_ref, clippy::cast_ref_to_mut, clippy::drop_ref)]
#[macro_use]
pub mod utils;

pub(self) mod snapshot_manager;
pub mod state;
pub mod state_manager;
pub mod state_root_with_aux_info;
#[macro_use]
pub mod storage_db;

pub mod tests;

mod impls;

/// Consensus parameter is only configurable in test mode.
#[derive(Debug, Clone)]
pub struct ConsensusParam {
    // The current delta switching rule is simply split by height at
    // multiple of SNAPSHOT_EPOCHS_CAPACITY.
    //
    // Only if we see problem dealing with attacks, consider rules like the
    // size of delta trie.
    pub snapshot_epoch_count: u32,
}

#[derive(Debug, Clone)]
pub struct StorageConfiguration {
    pub consensus_param: ConsensusParam,
    pub delta_mpts_cache_recent_lfu_factor: f64,
    pub delta_mpts_cache_start_size: u32,
    pub delta_mpts_cache_size: u32,
    pub delta_mpts_node_map_vec_size: u32,
    pub delta_mpts_slab_idle_size: u32,
    pub path_delta_mpts_dir: String,
    pub path_snapshot_dir: String,
}

impl StorageConfiguration {
    pub const DELTA_MPTS_DIR: &'static str = "./storage_db/delta_mpts/";
    pub const SNAPSHOT_DIR: &'static str = "./storage_db/snapshot/";
    pub const SNAPSHOT_INFO_DB_NAME: &'static str = "snapshot_info";
    pub const SNAPSHOT_INFO_DB_PATH: &'static str =
        "./storage_db/snapshot_info_db";
    /// Relative to Conflux data dir.
    // FIXME: but where is the data dir?
    #[allow(unused)]
    pub const STORAGE_DIR: &'static str = "./storage_db/";
}

impl Default for StorageConfiguration {
    fn default() -> Self {
        StorageConfiguration {
            consensus_param: ConsensusParam {
                snapshot_epoch_count: SNAPSHOT_EPOCHS_CAPACITY,
            },
            delta_mpts_cache_recent_lfu_factor:
                defaults::DEFAULT_DELTA_MPTS_CACHE_RECENT_LFU_FACTOR,
            delta_mpts_cache_size: defaults::DEFAULT_DELTA_MPTS_CACHE_SIZE,
            delta_mpts_cache_start_size:
                defaults::DEFAULT_DELTA_MPTS_CACHE_START_SIZE,
            delta_mpts_node_map_vec_size:
                defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER,
            delta_mpts_slab_idle_size:
                defaults::DEFAULT_DELTA_MPTS_SLAB_IDLE_SIZE,
            path_delta_mpts_dir: StorageConfiguration::DELTA_MPTS_DIR
                .to_string(),
            path_snapshot_dir: StorageConfiguration::SNAPSHOT_DIR.to_string(),
        }
    }
}

pub use self::{
    impls::{
        defaults,
        delta_mpt::*,
        errors::{Error, ErrorKind, Result},
        merkle_patricia_trie::{KVInserter, TrieProof},
        snapshot_sync::{FullSyncVerifier, MptSlicer},
        state_proof::StateProof,
        storage_db::{
            kvdb_rocksdb::KvdbRocksdb,
            kvdb_sqlite::{KvdbSqlite, KvdbSqliteStatements},
            snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
            sqlite::SqliteConnection,
        },
    },
    state::{State as StorageState, StateTrait as StorageStateTrait},
    state_manager::{
        StateIndex, StateManager as StorageManager,
        StateManagerTrait as StorageManagerTrait, StateReadonlyIndex,
    },
    state_root_with_aux_info::*,
    storage_db::KeyValueDbTrait,
};

#[cfg(test)]
pub use self::tests::new_state_manager_for_testing as new_storage_manager_for_testing;
use crate::parameters::consensus::SNAPSHOT_EPOCHS_CAPACITY;
