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

pub use self::{
    impls::{
        defaults,
        delta_mpt::*,
        errors::{Error, ErrorKind, Result},
        merkle_patricia_trie::{KVInserter, TrieProof},
        snapshot_sync::MptSlicer,
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
