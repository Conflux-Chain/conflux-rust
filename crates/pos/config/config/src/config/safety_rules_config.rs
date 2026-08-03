// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::config::OnDiskStorageConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: OnDiskStorageConfig,
    pub enable_cached_safety_data: bool,
}

impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: OnDiskStorageConfig::default(),
            enable_cached_safety_data: true,
        }
    }
}

impl SafetyRulesConfig {
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.backend.set_data_dir(data_dir);
    }
}
