// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use anyhow::Result;
use move_core_types::move_resource::MoveResource;
use serde::{Deserialize, Serialize};

/// Struct that represents a BaseUrlRotationEvent.
#[derive(Debug, Serialize, Deserialize)]
pub struct BaseUrlRotationEvent {
    new_base_url: Vec<u8>,
    time_rotated_seconds: u64,
}

impl BaseUrlRotationEvent {
    /// Get the new base url
    pub fn new_base_url(&self) -> &[u8] { &self.new_base_url }

    /// Get the (blockchain) time in seconds when the url was rotated
    pub fn time_rotated_seconds(&self) -> u64 { self.time_rotated_seconds }

    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

impl MoveResource for BaseUrlRotationEvent {
    const MODULE_NAME: &'static str = "DualAttestation";
    const STRUCT_NAME: &'static str = "BaseUrlRotationEvent";
}
