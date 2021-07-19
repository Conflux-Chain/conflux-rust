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

use crate::schema::{ensure_slice_len_eq, TERM_VDF_OUTPUT_CF_NAME};
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::mem::size_of;

define_schema!(
    TermVdfOutputSchema,
    u64, /* term num */
    Vec<u8>,
    TERM_VDF_OUTPUT_CF_NAME
);

impl KeyCodec<TermVdfOutputSchema> for u64 {
    fn encode_key(&self) -> Result<Vec<u8>> { Ok(self.to_be_bytes().to_vec()) }

    fn decode_key(mut data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;
        Ok(data.read_u64::<BigEndian>()?)
    }
}

impl ValueCodec<TermVdfOutputSchema> for Vec<u8> {
    fn encode_value(&self) -> Result<Vec<u8>> { Ok(self.clone()) }

    fn decode_value(data: &[u8]) -> Result<Self> { Ok(data.to_vec()) }
}
