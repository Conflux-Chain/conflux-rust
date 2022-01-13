// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_logger::{Level, CHANNEL_SIZE};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggerConfig {
    // channel size for the asychronous channel for node logging.
    pub chan_size: usize,
    // Use async logging
    pub is_async: bool,
    // The default logging level for slog.
    pub level: Level,
    pub file: Option<PathBuf>,
    // If this is None, we will not enable file rotation and
    // `rotation_file_size_mb` will not be used.
    pub rotation_count: Option<usize>,
    // The maximal file size before rotation.
    // The default value is set to 500MB.
    pub rotation_file_size_mb: Option<usize>,
}

impl Default for LoggerConfig {
    fn default() -> LoggerConfig {
        LoggerConfig {
            chan_size: CHANNEL_SIZE,
            is_async: true,
            level: Level::Info,
            file: None,
            rotation_count: None,
            rotation_file_size_mb: None,
        }
    }
}
