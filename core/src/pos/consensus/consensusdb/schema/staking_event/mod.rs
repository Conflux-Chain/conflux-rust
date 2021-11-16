// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module defines physical storage schema for StakingEvents
//! structure.
//!
//! Serialized StakingEvents identified by `epoch`.
//! ```text
//! |<---key--->|<---------------value------------->|
//! | epoch | staking_events bytes |
//! ```
//!
//! `epoch` is serialized in big endian so that records in RocksDB will be in
//! order of their numeric value.

use super::STAKING_EVENTS_CF_NAME;
use crate::pos::consensus::consensusdb::schema::ensure_slice_len_eq;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use cfx_types::H256;
use pow_types::StakingEvent;
use schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use std::mem::size_of;

define_schema!(
    StakingEventsSchema,
    u64, /* block id */
    (Vec<StakingEvent>, H256),
    STAKING_EVENTS_CF_NAME
);

impl KeyCodec<StakingEventsSchema> for u64 {
    fn encode_key(&self) -> Result<Vec<u8>> { Ok(self.to_be_bytes().to_vec()) }

    fn decode_key(mut data: &[u8]) -> Result<Self> {
        ensure_slice_len_eq(data, size_of::<Self>())?;
        Ok(data.read_u64::<BigEndian>()?)
    }
}

impl ValueCodec<StakingEventsSchema> for (Vec<StakingEvent>, H256) {
    fn encode_value(&self) -> Result<Vec<u8>> {
        bcs::to_bytes(self).map_err(Into::into)
    }

    fn decode_value(data: &[u8]) -> Result<Self> {
        bcs::from_bytes(data).map_err(Into::into)
    }
}
