// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Result};

use schemadb::ColumnFamilyName;

pub(crate) mod block;
pub(crate) mod ledger_block;
pub(crate) mod quorum_certificate;
pub(crate) mod single_entry;

pub(super) const BLOCK_CF_NAME: ColumnFamilyName = "block";
pub(super) const QC_CF_NAME: ColumnFamilyName = "quorum_certificate";
pub(super) const SINGLE_ENTRY_CF_NAME: ColumnFamilyName = "single_entry";
pub(super) const LEDGER_BLOCK_CF_NAME: ColumnFamilyName = "ledger_block";

fn ensure_slice_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}
