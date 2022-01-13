// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_metrics::{register_int_counter, IntCounter};
use once_cell::sync::Lazy;

pub static DIEM_JELLYFISH_LEAF_ENCODED_BYTES: Lazy<IntCounter> =
    Lazy::new(|| {
        register_int_counter!(
            "diem_jellyfish_leaf_encoded_bytes",
            "Diem jellyfish leaf encoded bytes in total"
        )
        .unwrap()
    });

pub static DIEM_JELLYFISH_INTERNAL_ENCODED_BYTES: Lazy<IntCounter> =
    Lazy::new(|| {
        register_int_counter!(
            "diem_jellyfish_internal_encoded_bytes",
            "Diem jellyfish total internal nodes encoded in bytes"
        )
        .unwrap()
    });

pub static DIEM_JELLYFISH_STORAGE_READS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "diem_jellyfish_storage_reads",
        "Diem jellyfish reads from storage"
    )
    .unwrap()
});
