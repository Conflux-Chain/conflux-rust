// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::consensus::counters;
use diem_infallible::duration_since_epoch;
use std::time::Duration;

pub struct BlockStage;

impl BlockStage {
    pub const COMMITTED: &'static str = "committed";
    pub const EXECUTED: &'static str = "executed";
    pub const QC_ADDED: &'static str = "qc_added";
    pub const QC_AGGREGATED: &'static str = "qc_aggregated";
    pub const RECEIVED: &'static str = "received";
    pub const SIGNED: &'static str = "signed";
    pub const SYNCED: &'static str = "synced";
    pub const VOTED: &'static str = "voted";
}

/// Record the time during each stage of a block.
pub fn observe_block(timestamp: u64, stage: &'static str) {
    if let Some(t) =
        duration_since_epoch().checked_sub(Duration::from_micros(timestamp))
    {
        counters::BLOCK_TRACING
            .with_label_values(&[stage])
            .observe(t.as_secs_f64());
    }
}
