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
    // FIXME: prefix with delta.
    pub cache_start_size: u32,
    pub cache_size: u32,
    pub idle_size: u32,
    pub node_map_size: u32,
    pub recent_lfu_factor: f64,
    // FIXME: add paths here.
    pub consensus_param: ConsensusParam,
}

impl Default for StorageConfiguration {
    fn default() -> Self {
        StorageConfiguration {
            cache_start_size: defaults::DEFAULT_CACHE_START_SIZE,
            cache_size: defaults::DEFAULT_CACHE_SIZE,
            idle_size: defaults::DEFAULT_IDLE_SIZE,
            node_map_size: defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER,
            recent_lfu_factor: defaults::DEFAULT_RECENT_LFU_FACTOR,
            consensus_param: ConsensusParam {
                snapshot_epoch_count: SNAPSHOT_EPOCHS_CAPACITY,
            },
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
            kvdb_rocksdb::KvdbRocksdb, kvdb_sqlite::KvdbSqlite,
            snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
            sqlite::SqliteConnection,
        },
        storage_manager::DeltaMptIterator,
    },
    state::{State as Storage, StateTrait as StorageTrait},
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
