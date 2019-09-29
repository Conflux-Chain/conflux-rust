// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
pub mod utils;

pub(self) mod snapshot_manager;
pub mod state;
pub mod state_manager;
#[macro_use]
pub mod storage_db;

pub mod tests;

mod impls;

pub use self::impls::state_proof::{StateProof, TrieProof};

pub use self::{
    impls::{
        defaults,
        errors::{Error, ErrorKind, Result},
        multi_version_merkle_patricia_trie::{
            guarded_value::GuardedValue, MultiVersionMerklePatriciaTrie,
        },
        snapshot_sync::MptSlicer,
        storage_db::{
            kvdb_rocksdb::KvdbRocksdb, kvdb_sqlite::KvdbSqlite,
            snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
            sqlite::SqliteConnection,
        },
    },
    state::{State as Storage, StateTrait as StorageTrait},
    state_manager::{
        SnapshotAndEpochIdRef, StateManager as StorageManager,
        StateManagerTrait as StorageManagerTrait,
    },
    storage_db::KeyValueDbTrait,
    tests::new_state_manager_for_testing as new_storage_manager_for_testing,
};
