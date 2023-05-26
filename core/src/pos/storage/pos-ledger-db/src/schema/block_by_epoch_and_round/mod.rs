// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::schema::{ensure_slice_len_eq, BLOCK_BY_EPOCH_AND_ROUND_CF_NAME};
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use diem_crypto::HashValue;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::mem::size_of;

define_schema!(
    BlockByEpochAndRoundSchema,
    Key, /* epoch num */
    HashValue,
    BLOCK_BY_EPOCH_AND_ROUND_CF_NAME
);

/// (epoch, round)
type Key = (u64, u64);

impl KeyCodec<BlockByEpochAndRoundSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let (epoch, round) = *self;

        let mut encoded_key = Vec::with_capacity(size_of::<u64>() * 2);
        encoded_key.write_u64::<BigEndian>(epoch)?;
        encoded_key.write_u64::<BigEndian>(round)?;
        Ok(encoded_key)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;

        let epoch_size = size_of::<u64>();

        let epoch = (&data[..epoch_size]).read_u64::<BigEndian>()?;
        let round = (&data[epoch_size..]).read_u64::<BigEndian>()?;
        Ok((epoch, round))
    }
}

impl ValueCodec<BlockByEpochAndRoundSchema> for HashValue {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
}
