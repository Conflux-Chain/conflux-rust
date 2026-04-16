// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_temppath::TempPath;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestConfig {
    // Used only to prevent a potentially temporary data_dir from being
    // deleted. This should eventually be moved to be owned by something
    // outside the config.
    #[serde(skip)]
    temp_dir: Option<TempPath>,
}

impl Clone for TestConfig {
    fn clone(&self) -> Self { Self { temp_dir: None } }
}

impl PartialEq for TestConfig {
    fn eq(&self, _other: &Self) -> bool { true }
}

impl TestConfig {
    pub fn open_module() -> Self { Self { temp_dir: None } }

    pub fn new_with_temp_dir(temp_dir: Option<TempPath>) -> Self {
        let temp_dir = temp_dir.unwrap_or_else(|| {
            let temp_dir = TempPath::new();
            temp_dir.create_as_dir().expect("error creating tempdir");
            temp_dir
        });
        Self {
            temp_dir: Some(temp_dir),
        }
    }

    pub fn temp_dir(&self) -> Option<&Path> {
        self.temp_dir.as_ref().map(|temp_dir| temp_dir.path())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_test_config_equality() {
        // Create default test config
        let test_config = TestConfig::new_with_temp_dir(None);

        // Clone the config and verify equality
        let clone_test_config = test_config.clone();
        assert_eq!(clone_test_config, test_config);
    }
}
