// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
    // FIXME(thegaram): currently we're using the epoch log index here
    pub log_index: Option<U256>,
    /// Log Index in Transaction
    pub transaction_log_index: Option<U256>,
    /// Whether Log Type is Removed (Geth Compatibility Field)
    #[serde(default)]
    pub removed: bool,
}

impl Log {
    pub fn try_from_localized(
        e: LocalizedLogEntry, consensus: SharedConsensusGraph,
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
            removed: false,
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
