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

use crate::rpc::{
    error_codes::{internal_error, invalid_params},
    types::Bytes,
};
use cfx_types::{H160, H256, U256};
use cfxcore::SharedConsensusGraph;
use jsonrpc_core::Error as RpcError;
use primitives::{
    log_entry::{LocalizedLogEntry, LogEntry},
    EpochNumber,
};

/// Log
#[derive(Debug, Serialize, PartialEq, Eq, Hash, Clone)]
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
        e: LocalizedLogEntry, consensus: SharedConsensusGraph, removed: bool,
    ) -> Result<Log, RpcError> {
        // find pivot hash
        let epoch = consensus
            .get_block_epoch_number(&e.block_hash)
            .ok_or(invalid_params("blockHash", "Unknown block"))?;

        let hashes = consensus
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch))
            .map_err(|_| invalid_params("blockHash", "Unknown block"))?;

        let pivot_hash =
            hashes.last().ok_or(internal_error("Inconsistent state"))?;

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

/*
#[cfg(test)]
mod tests {
    use ethereum_types::{H160, H256, U256};
    use serde_json;
    use std::str::FromStr;
    use v1::types::Log;

    #[test]
    fn log_serialization() {
        let s = r#"{"address":"0x33990122638b9132ca29c723bdf037f1a891a70c","topics":["0xa6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc","0x4861736852656700000000000000000000000000000000000000000000000000"],"data":"0x","blockHash":"0xed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5","blockNumber":"0x4510c","transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x0","logIndex":"0x1","transactionLogIndex":"0x1","type":"mined","removed":false}"#;

        let log = Log {
            address: H160::from_str("33990122638b9132ca29c723bdf037f1a891a70c").unwrap(),
            topics: vec![
                H256::from_str("a6697e974e6a320f454390be03f74955e8978f1a6971ea6730542e37b66179bc")
                    .unwrap(),
                H256::from_str("4861736852656700000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ],
            data: vec![].into(),
            block_hash: Some(
                H256::from_str("ed76641c68a1c641aee09a94b3b471f4dc0316efe5ac19cf488e2674cf8d05b5")
                    .unwrap(),
            ),
            block_number: Some(U256::from(0x4510c)),
            transaction_hash: Some(H256::default()),
            transaction_index: Some(U256::default()),
            transaction_log_index: Some(1.into()),
            log_index: Some(U256::from(1)),
            removed: false,
        };

        let serialized = serde_json::to_string(&log).unwrap();
        assert_eq!(serialized, s);
    }
}
 */
