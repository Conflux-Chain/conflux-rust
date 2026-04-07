// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_metrics::{
    register_histogram_vec, register_int_counter, register_int_gauge,
    register_int_gauge_vec, HistogramVec, IntCounter, IntGauge, IntGaugeVec,
};
use once_cell::sync::Lazy;

pub static DIEM_STORAGE_COMMITTED_TXNS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "diem_storage_committed_txns",
        "Diem storage committed transactions"
    )
    .unwrap()
});

pub static DIEM_STORAGE_LATEST_TXN_VERSION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_storage_latest_transaction_version",
        "Diem storage latest transaction version"
    )
    .unwrap()
});

pub static DIEM_STORAGE_LEDGER_VERSION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_storage_ledger_version",
        "Version in the latest saved ledger info."
    )
    .unwrap()
});

pub static DIEM_STORAGE_NEXT_BLOCK_EPOCH: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "diem_storage_next_block_epoch",
        "ledger_info.next_block_epoch() for the latest saved ledger info."
    )
    .unwrap()
});

pub static DIEM_STORAGE_API_LATENCY_SECONDS: Lazy<HistogramVec> =
    Lazy::new(|| {
        register_histogram_vec!(
            // metric name
            "diem_storage_api_latency_seconds",
            // metric description
            "Diem storage api latency in seconds",
            // metric labels (dimensions)
            &["api_name", "result"]
        )
        .unwrap()
    });

pub static DIEM_STORAGE_OTHER_TIMERS_SECONDS: Lazy<HistogramVec> =
    Lazy::new(|| {
        register_histogram_vec!(
            // metric name
            "diem_storage_other_timers_seconds",
            // metric description
            "Various timers below public API level.",
            // metric labels (dimensions)
            &["name"]
        )
        .unwrap()
    });

/// Rocksdb metrics
pub static DIEM_STORAGE_ROCKSDB_PROPERTIES: Lazy<IntGaugeVec> =
    Lazy::new(|| {
        register_int_gauge_vec!(
            // metric name
            "diem_rocksdb_properties",
            // metric description
            "rocksdb integer properties",
            // metric labels (dimensions)
            &["cf_name", "property_name",]
        )
        .unwrap()
    });
