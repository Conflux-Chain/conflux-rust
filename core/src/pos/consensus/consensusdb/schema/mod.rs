// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use anyhow::{ensure, Result};

use schemadb::ColumnFamilyName;

pub(crate) mod block;
pub(crate) mod ledger_block;
pub(crate) mod quorum_certificate;
pub(crate) mod single_entry;
pub(crate) mod staking_event;

pub(super) const BLOCK_CF_NAME: ColumnFamilyName = "block";
pub(super) const QC_CF_NAME: ColumnFamilyName = "quorum_certificate";
pub(super) const SINGLE_ENTRY_CF_NAME: ColumnFamilyName = "single_entry";
pub(super) const LEDGER_BLOCK_CF_NAME: ColumnFamilyName = "ledger_block";
pub(super) const STAKING_EVENTS_CF_NAME: ColumnFamilyName = "staking_event";

fn ensure_slice_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}
