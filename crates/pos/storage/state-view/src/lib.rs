// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! This crate defines [`trait StateView`](StateView).

use diem_crypto::HashValue;
use diem_types::term_state::PosState;

/// A read-only snapshot of the global PoS state, passed to the VM for
/// transaction execution.
pub trait StateView: Sync {
    /// For logging and debugging purpose, identifies what this view is
    /// for.
    fn id(&self) -> StateViewId { StateViewId::Miscellaneous }

    /// Returns the PoS state for this view.
    fn pos_state(&self) -> &PosState;
}

#[derive(Copy, Clone)]
pub enum StateViewId {
    /// Executor applying a block.
    BlockExecution { block_id: HashValue },
    /// For test, db-bootstrapper, etc.
    Miscellaneous,
}
