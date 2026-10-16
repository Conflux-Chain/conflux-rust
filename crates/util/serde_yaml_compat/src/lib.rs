// Copyright 2026 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Route log4rs's serde_yaml 0.9 dependency to the maintained YAML backend.
//! This adapter preserves log4rs's existing file-loading and reload behavior.

#![forbid(unsafe_code)]

pub use yaml_serde::*;
