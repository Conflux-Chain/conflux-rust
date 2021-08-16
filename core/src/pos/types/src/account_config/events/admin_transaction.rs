// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use anyhow::Result;
use move_core_types::move_resource::MoveResource;
use serde::{Deserialize, Serialize};

/// Struct that represents a AdminEvent.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminTransactionEvent {
    committed_timestamp_secs: u64,
}

impl AdminTransactionEvent {
    /// Get the applied writeset.
    pub fn committed_timestamp_secs(&self) -> u64 {
        self.committed_timestamp_secs
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

impl MoveResource for AdminTransactionEvent {
    const MODULE_NAME: &'static str = "DiemAccount";
    const STRUCT_NAME: &'static str = "AdminTransactionEvent";
}
