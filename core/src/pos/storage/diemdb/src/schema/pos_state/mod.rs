// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines physical storage schema for LedgerInfoWithSignatures
//! structure.
//!
//! Serialized LedgerInfoWithSignatures identified by `epoch`.
//! ```text
//! |<---key--->|<---------------value------------->|
//! | epoch | ledger_info_with_signatures bytes |
//! ```
//!
//! `epoch` is serialized in big endian so that records in RocksDB will be in
//! order of their numeric value.

use anyhow::Result;
use diem_crypto::hash::HashValue;
use diem_types::{ledger_info::LedgerInfoWithSignatures, term_state::PosState};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
    DEFAULT_CF_NAME,
};

define_schema!(
    PosStateSchema,
    HashValue, /* block id */
    PosState,
    DEFAULT_CF_NAME
);

impl KeyCodec<PosStateSchema> for HashValue {
    fn encode_key(&self) -> Result<Vec<u8>> { Ok(self.to_vec()) }

    fn decode_key(data: &[u8]) -> Result<Self> {
        Self::from_slice(data).map_err(Into::into)
    }
}

impl ValueCodec<PosStateSchema> for PosState {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod test;
