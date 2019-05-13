// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO(yz): remember to remove.
#![allow(dead_code, unused_variables)]

pub mod state;
pub mod state_manager;

pub mod tests;

mod impls;

pub use self::{
    impls::{
        defaults,
        errors::{Error, ErrorKind, Result},
        multi_version_merkle_patricia_trie::{
            guarded_value::GuardedValue, merkle_patricia_trie::MerkleHash,
        },
    },
    state::{State as Storage, StateTrait as StorageTrait},
    state_manager::{
        StateManager as StorageManager,
        StateManagerTrait as StorageManagerTrait,
    },
};
