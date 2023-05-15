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
#[cfg(feature = "light-hash")]
extern crate blake2_hasher;
extern crate profile;

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

#[cfg(feature = "lvmt-storage")]
mod amt_impls;
mod impls;
#[cfg(feature = "mpt-storage")]
mod mpt_impls;
#[cfg(feature = "rain-storage")]
mod rain_impls;
#[cfg(feature = "raw-storage")]
mod raw_impls;

use metrics::{
    register_meter_with_group, register_timer_with_group, Meter, Timer,
};
use std::sync::Arc;

lazy_static! {
    static ref STORAGE_GET_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "storage::get");
    static ref STORAGE_GET_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "storage::get_timer");
    static ref STORAGE_SET_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "storage::set");
    static ref STORAGE_SET_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "storage::set_timer");
    static ref STORAGE_COMMIT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "storage::commit");
    static ref STORAGE_COMMIT_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "storage::commit_timer");
}

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

#[cfg(feature = "lvmt-storage")]
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
#[cfg(feature = "rain-storage")]
pub use self::rain_impls::{
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
#[cfg(feature = "raw-storage")]
pub use self::raw_impls::{
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

#[cfg(feature = "light-hash")]
use blake2_hasher::blake2b as hash;
#[cfg(not(feature = "light-hash"))]
use keccak_hash::keccak as hash;

#[allow(dead_code)]
fn convert_key(access_key: primitives::StorageKey) -> cfx_types::H256 {
    hash(access_key.to_key_bytes())
}
