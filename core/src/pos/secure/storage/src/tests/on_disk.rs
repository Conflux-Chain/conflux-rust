// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{tests::suite, OnDiskStorage, Storage};
use diem_temppath::TempPath;

#[test]
fn on_disk() {
    let path_buf = TempPath::new().path().to_path_buf();
    let mut storage = Storage::from(OnDiskStorage::new(path_buf));
    suite::execute_all_storage_tests(&mut storage);
}
