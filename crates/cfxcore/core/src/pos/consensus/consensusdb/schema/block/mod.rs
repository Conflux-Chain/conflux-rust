// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module defines physical storage schema for consensus block.
//!
//! Serialized block bytes identified by block_hash.
//! ```text
//! |<---key---->|<---value--->|
//! | block_hash |    block    |
//! ```

use super::BLOCK_CF_NAME;
use anyhow::Result;
use consensus_types::block::{Block, BlockUnchecked};
use diem_crypto::HashValue;
use schemadb::schema::{KeyCodec, Schema, ValueCodec};

pub struct BlockSchema;

impl Schema for BlockSchema {
    type Key = HashValue;
    type Value = Block;

    const COLUMN_FAMILY_NAME: schemadb::ColumnFamilyName = BLOCK_CF_NAME;
}

impl KeyCodec<BlockSchema> for HashValue {
    fn encode_key(&self) -> Result<Vec<u8>> { Ok(self.to_vec()) }

    fn decode_key(data: &[u8]) -> Result<Self> {
        Ok(HashValue::from_slice(data)?)
    }
}

impl ValueCodec<BlockSchema> for Block {
    fn encode_value(&self) -> Result<Vec<u8>> { Ok(bcs::to_bytes(&self)?) }

    fn decode_value(data: &[u8]) -> Result<Self> {
        Ok(bcs::from_bytes::<BlockUnchecked>(data).map(Into::into)?)
    }
}

#[cfg(test)]
mod test;
