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
use cfx_rpc_cfx_types::traits::BlockProvider;
use cfx_types::{H160, H256, U256};
use primitives::{
    log_entry::{LocalizedLogEntry, LogEntry},
    EpochNumber,
};
use serde::{Deserialize, Serialize};

/// Log
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    /// H160
    pub address: H160,
    /// Topics
    pub topics: Vec<H256>,
    /// Data
    pub data: Bytes,
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
            address: e.entry.address,
            topics: e.entry.topics.into_iter().map(Into::into).collect(),
            data: e.entry.data.into(),
            block_hash: *pivot_hash,
            // note: blocks in EVM space RPCs correspond to epochs
            block_number: e.epoch_number.into(),
            transaction_hash: e.transaction_hash.into(),
            transaction_index: e.transaction_index.into(),
            log_index: Some(e.log_index.into()),
            transaction_log_index: Some(e.transaction_log_index.into()),
            removed,
        })
    }

    pub fn try_from(_e: LogEntry) -> Result<Log, String> {
        unimplemented!();
        // Ok(Log {
        //     address: RpcAddress::try_from_h160(e.address, network)?,
        //     topics: e.topics.into_iter().map(Into::into).collect(),
        //     data: e.data.into(),
        //     block_hash: None,
        //     epoch_number: None,
        //     transaction_hash: None,
        //     transaction_index: None,
        //     log_index: None,
        //     transaction_log_index: None,
        // })
    }
}
