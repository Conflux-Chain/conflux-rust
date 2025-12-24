// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use crate::{Bytes, Error};
use alloy_primitives::Log as AlloyLogData;
use alloy_primitives_wrapper::{WAddress, WB256};
use alloy_rpc_types_eth::Log as AlloyLog;
use cfx_rpc_cfx_types::traits::BlockProvider;
use cfx_types::{H160, H256, U256, U64};
use primitives::{
    log_entry::{LocalizedLogEntry, LogEntry},
    EpochNumber,
};
use serde::{Deserialize, Serialize};

/// Log
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    #[serde(flatten)]
    /// Consensus log object
    pub inner: LogData,
    /// Block Hash
    pub block_hash: H256,
    /// Block Number
    pub block_number: U256,
    /// Transaction Hash
    pub transaction_hash: H256,
    /// Transaction Index
    pub transaction_index: U256,
    /// Log Index in Block
    pub log_index: Option<U256>,
    /// Log Index in Transaction
    pub transaction_log_index: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block_timestamp: Option<U64>,
    /// Whether Log Type is Removed (Geth Compatibility Field)
    #[serde(default)]
    pub removed: bool,
}

impl Log {
    pub fn try_from_localized(
        e: LocalizedLogEntry, consensus: impl BlockProvider, removed: bool,
    ) -> Result<Log, Error> {
        // find pivot hash
        let epoch = consensus.get_block_epoch_number(&e.block_hash).ok_or(
            Error::InvalidParams(
                "blockHash".to_string(),
                "Unknown block".to_string(),
            ),
        )?;

        let hashes = consensus
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch))
            .map_err(|_| {
                Error::InvalidParams(
                    "blockHash".to_string(),
                    "Unknown block".to_string(),
                )
            })?;

        let pivot_hash = hashes
            .last()
            .ok_or(Error::InternalError("Inconsistent state".to_string()))?;

        // construct RPC log
        Ok(Log {
            inner: LogData {
                address: e.entry.address,
                topics: e.entry.topics.into_iter().map(Into::into).collect(),
                data: e.entry.data.into(),
            },
            block_hash: *pivot_hash,
            // note: blocks in EVM space RPCs correspond to epochs
            block_number: e.epoch_number.into(),
            block_timestamp: e.block_timestamp.map(Into::into),
            transaction_hash: e.transaction_hash.into(),
            transaction_index: e.transaction_index.into(),
            log_index: Some(e.log_index.into()),
            transaction_log_index: Some(e.transaction_log_index.into()),
            removed,
        })
    }

    pub fn from_localized(
        e: LocalizedLogEntry, epoch_hash: H256, removed: bool,
    ) -> Log {
        Log {
            inner: LogData {
                address: e.entry.address,
                topics: e.entry.topics.into_iter().map(Into::into).collect(),
                data: e.entry.data.into(),
            },
            block_hash: epoch_hash,
            // note: blocks in EVM space RPCs correspond to epochs
            block_number: e.epoch_number.into(),
            block_timestamp: e.block_timestamp.map(Into::into),
            transaction_hash: e.transaction_hash.into(),
            transaction_index: e.transaction_index.into(),
            log_index: Some(e.log_index.into()),
            transaction_log_index: Some(e.transaction_log_index.into()),
            removed,
        }
    }

    pub fn try_from(_e: LogEntry) -> Result<Log, String> {
        unimplemented!();
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct LogData {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

impl From<Log> for AlloyLog {
    fn from(log: Log) -> Self {
        let inner = AlloyLogData {
            address: WAddress::from(log.inner.address).into(),
            data: alloy_primitives::LogData::new(
                log.inner
                    .topics
                    .into_iter()
                    .map(|h| WB256::from(h).into())
                    .collect(),
                log.inner.data.0.into(),
            )
            .expect("Log data is always valid"),
        };
        AlloyLog {
            inner,
            block_hash: Some(WB256::from(log.block_hash).into()),
            block_number: Some(log.block_number.as_u64()),
            block_timestamp: log.block_timestamp.map(|v| v.as_u64()),
            transaction_hash: Some(WB256::from(log.transaction_hash).into()),
            transaction_index: Some(log.transaction_index.as_u64()),
            log_index: log.log_index.map(|v| v.as_u64()),
            removed: log.removed,
        }
    }
}
