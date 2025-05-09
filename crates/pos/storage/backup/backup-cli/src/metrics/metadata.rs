// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_secure_push_metrics::{register_int_gauge, IntGauge};
use once_cell::sync::Lazy;

pub static NUM_META_FILES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_backup_metadata_num_files",
        "Number of metadata files in total."
    )
    .unwrap()
});

pub static NUM_META_MISS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_backup_metadata_num_file_cache_misses",
        "Number of metadata files to download due to non-existence in local cache."
    )
    .unwrap()
});

pub static NUM_META_DOWNLOAD: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_backup_metadata_num_file_downloads",
        "Number of metadata files to download due to non-existence in local cache."
    )
    .unwrap()
});
