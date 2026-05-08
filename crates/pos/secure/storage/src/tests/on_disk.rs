// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{tests::suite, OnDiskStorage};
use tempfile::TempDir;

#[test]
fn on_disk() {
    let dir = TempDir::new().unwrap();
    let mut storage = OnDiskStorage::new(dir.path().join("storage.json"));
    suite::execute_all_storage_tests(&mut storage);
}
