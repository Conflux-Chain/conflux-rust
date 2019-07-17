// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub(self) mod snapshot_manager;
pub mod state;
pub mod state_manager;
pub(self) mod storage_db;

pub mod tests;

mod impls;

pub use self::{
    impls::{
        defaults,
        errors::{Error, ErrorKind, Result},
        multi_version_merkle_patricia_trie::guarded_value::GuardedValue,
    },
    state::{State as Storage, StateTrait as StorageTrait},
    state_manager::{
        SnapshotAndEpochIdRef, StateManager as StorageManager,
        StateManagerTrait as StorageManagerTrait,
    },
    tests::new_state_manager_for_testing as new_storage_manager_for_testing,
};
