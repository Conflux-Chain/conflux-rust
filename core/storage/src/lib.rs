// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO: check them again and reason about the safety of each usage.
#![allow(clippy::mut_from_ref, clippy::cast_ref_to_mut, clippy::drop_ref)]
// Recursion limit raised for error_chain
#![recursion_limit = "512"]
#![allow(deprecated)]

//extern crate futures;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

#[macro_use]
pub mod utils;

pub mod state;
mod state_manager;

#[macro_use]
mod storage_db;

#[cfg(any(test, feature = "testonly_code"))]
pub mod tests;
#[cfg(not(any(test, feature = "testonly_code")))]
mod tests;

#[cfg(feature = "amt-storage")]
mod amt_impls;
mod impls;
#[cfg(feature = "mpt-storage")]
mod mpt_impls;

pub type WithProof = primitives::static_bool::Yes;
pub type NoProof = primitives::static_bool::No;

// Export all the config info
pub use self::impls::{
    config::storage_manager::{ConsensusParam, ProvideExtraSnapshotSyncConfig},
    defaults::{self, DEFAULT_EXECUTION_PREFETCH_THREADS},
};

// Common tools not only for deltampt.
pub use self::{
    impls::{
        errors::{Error, ErrorKind, Result},
        merkle_patricia_trie::{simple_mpt::*, MptKeyValue, TrieProof},
        storage_db::{
            kvdb_rocksdb::KvdbRocksdb,
            kvdb_sqlite::{KvdbSqlite, KvdbSqliteStatements},
        },
    },
    storage_db::{snapshot_db::SnapshotInfo, KeyValueDbTrait},
};

#[cfg(feature = "amt-storage")]
pub use self::amt_impls::{
    config::storage_dir,
    config::storage_manager::StorageConfiguration,
    proof_type::{StateProof, StorageRootProof},
    state::State as StorageState,
    state_index::StateIndex,
    state_manager::StateManager as StorageManager,
    state_trait::StateManagerTrait as StorageManagerTrait,
    state_trait::StateTrait as StorageStateTrait,
    state_trait::StateTraitExt as StorageStateTraitExt,
};
#[cfg(feature = "mpt-storage")]
pub use self::mpt_impls::{
    config::storage_dir,
    config::storage_manager::StorageConfiguration,
    proof_type::{StateProof, StorageRootProof},
    state::State as StorageState,
    state_index::StateIndex,
    state_manager::StateManager as StorageManager,
    state_trait::StateManagerTrait as StorageManagerTrait,
    state_trait::StateTrait as StorageStateTrait,
    state_trait::StateTraitExt as StorageStateTraitExt,
};
#[cfg(not(feature = "storage-dev"))]
pub use self::{
    impls::config::storage_manager::storage_dir,
    state::{
        State as StorageState, StateProof, StateTrait as StorageStateTrait,
        StateTraitExt as StorageStateTraitExt, StorageRootProof,
    },
    state_manager::{
        StateIndex, StateManager as StorageManager,
        StateManagerTrait as StorageManagerTrait, StorageConfiguration,
    },
};

#[cfg(not(feature = "storage-dev"))]
pub use self::{
    impls::{
        merkle_patricia_trie::KVInserter,
        snapshot_sync::{FullSyncVerifier, MptSlicer},
        storage_db::snapshot_db_manager_sqlite::SnapshotDbManagerSqlite as SnapshotDbManager,
    },
    storage_db::{
        key_value_db::KeyValueDbIterableTrait,
        snapshot_db::{OpenSnapshotMptTrait, SnapshotDbTrait},
        SnapshotDbManagerTrait,
    },
};

#[cfg(any(test, feature = "testonly_code"))]
pub use self::{
    impls::delta_mpt::delta_mpt_iterator::DeltaMptIterator,
    tests::new_state_manager_for_unit_test as new_storage_manager_for_testing,
};
