// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{tests::suite, OnDiskStorage};
use tempfile::NamedTempFile;

#[test]
fn on_disk() {
    let path_buf = NamedTempFile::new()
        .unwrap()
        .into_temp_path()
        .keep()
        .unwrap();
    let mut storage = OnDiskStorage::new(path_buf);
    suite::execute_all_storage_tests(&mut storage);
}
