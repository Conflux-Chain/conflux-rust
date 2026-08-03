// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use schemadb::SchemaBatch;

/// Structure that collects changes to be made to the DB in one transaction.
///
/// This is required to be converted to `SealedChangeSet` before committing
/// to the DB.
pub(crate) struct ChangeSet {
    /// A batch of db alternations.
    pub batch: SchemaBatch,
}

impl ChangeSet {
    /// Constructor.
    pub fn new() -> Self {
        Self {
            batch: SchemaBatch::new(),
        }
    }
}

/// ChangeSet that's ready to be committed to the DB.
///
/// This is a wrapper type just to make sure `ChangeSet` to be committed is
/// sealed properly.
pub(crate) struct SealedChangeSet {
    /// A batch of db alternations.
    pub batch: SchemaBatch,
}
