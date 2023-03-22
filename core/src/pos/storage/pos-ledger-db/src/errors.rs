// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module defines error types used by [`PosLedgerDB`](crate::PosLedgerDB).

use thiserror::Error;

/// This enum defines errors commonly used among
/// [`PosLedgerDB`](crate::PosLedgerDB) APIs.
#[derive(Debug, Error)]
pub enum DiemDbError {
    /// A requested item is not found.
    #[error("{0} not found.")]
    NotFound(String),
    /// Requested too many items.
    #[error("Too many items requested: at least {0} requested, max is {1}")]
    TooManyRequested(u64, u64),
}
