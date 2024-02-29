// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! This crate defines [`trait StateView`](StateView).

use anyhow::Result;
use diem_crypto::HashValue;
use diem_types::{
    access_path::AccessPath, term_state::PosState, transaction::Version,
};

/// `StateView` is a trait that defines a read-only snapshot of the global
/// state. It is passed to the VM for transaction execution, during which the VM
/// is guaranteed to read anything at the given state.
pub trait StateView: Sync {
    /// For logging and debugging purpose, identifies what this view is for.
    fn id(&self) -> StateViewId { StateViewId::Miscellaneous }

    /// Gets the state for a single access path.
    fn get(&self, access_path: &AccessPath) -> Result<Option<Vec<u8>>>;

    /// Gets states for a list of access paths.
    fn multi_get(
        &self, access_paths: &[AccessPath],
    ) -> Result<Vec<Option<Vec<u8>>>>;

    /// VM needs this method to know whether the current state view is for
    /// genesis state creation. Currently TransactionPayload::WriteSet is
    /// only valid for genesis state creation.
    fn is_genesis(&self) -> bool;

    fn pos_state(&self) -> &PosState;
}

#[derive(Copy, Clone)]
pub enum StateViewId {
    /// State-sync applying a chunk of transactions.
    ChunkExecution { first_version: Version },
    /// LEC applying a block.
    BlockExecution { block_id: HashValue },
    /// VmValidator verifying incoming transaction.
    TransactionValidation { base_version: Version },
    /// For test, db-bootstrapper, etc. Usually not aimed to pass to VM.
    Miscellaneous,
}
