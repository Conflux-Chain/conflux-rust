// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{access_path::AccessPath, transaction::Version};
use anyhow::Result;

// TODO combine with ConfigStorage
pub trait MoveStorage {
    /// Returns a vector of Move resources as serialized byte array
    /// Order of resources returned matches the order of `access_path`
    fn batch_fetch_resources(
        &self, access_paths: Vec<AccessPath>,
    ) -> Result<Vec<Vec<u8>>>;

    /// Returns a vector of Move resources as serialized byte array from a
    /// specified version of the database
    /// Order of resources returned matches the order of `access_path`
    fn batch_fetch_resources_by_version(
        &self, access_paths: Vec<AccessPath>, version: Version,
    ) -> Result<Vec<Vec<u8>>>;

    /// Get the version on the latest transaction info.
    fn fetch_synced_version(&self) -> Result<Version>;
}
