// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module defines physical storage schema for the QC ledger info whose
//! signatures vote for a block, identified by that voted block's id.

use crate::schema::LEDGER_INFO_BY_VOTED_BLOCK_CF_NAME;
use anyhow::Result;
use diem_crypto::hash::HashValue;
use diem_types::ledger_info::{
    LedgerInfoWithSignatures, LedgerInfoWithSignaturesUnchecked,
};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};

define_schema!(
    LedgerInfoByVotedBlockSchema,
    HashValue, /* block id */
    LedgerInfoWithSignatures,
    LEDGER_INFO_BY_VOTED_BLOCK_CF_NAME
);

impl KeyCodec<LedgerInfoByVotedBlockSchema> for HashValue {
    fn encode_key(&self) -> Result<Vec<u8>> { Ok(self.to_vec()) }

    fn decode_key(data: &[u8]) -> Result<Self> {
        Self::from_slice(data).map_err(Into::into)
    }
}

impl ValueCodec<LedgerInfoByVotedBlockSchema> for LedgerInfoWithSignatures {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes::<LedgerInfoWithSignaturesUnchecked>(data)
            .map(Into::into)
            .map_err(Into::into)
    }
}
