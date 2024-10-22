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

use crate::{BlockNumber, Error as SelfError, Log};
use cfx_rpc_cfx_types::traits::BlockProvider;
use cfx_rpc_primitives::VariadicValue;
use cfx_types::{Space, H160, H256};
use primitives::{
    filter::{LogFilter as PrimitiveFilter, LogFilterParams},
    EpochNumber,
};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::convert::TryInto;

/// Filter Address
pub type FilterAddress = VariadicValue<H160>;
/// Topic
pub type Topic = VariadicValue<H256>;

/// Filter
#[derive(Debug, PartialEq, Clone, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct EthRpcLogFilter {
    /// From Block
    pub from_block: Option<BlockNumber>,
    /// To Block
    pub to_block: Option<BlockNumber>,
    /// Block hash
    pub block_hash: Option<H256>,
    /// Address
    pub address: Option<FilterAddress>,
    /// Topics
    pub topics: Option<Vec<Topic>>,
}

impl EthRpcLogFilter {
    pub fn into_primitive(
        self, consensus: impl BlockProvider,
    ) -> Result<PrimitiveFilter, SelfError> {
        let params = LogFilterParams {
            address: self.address.map(|v| v.to_vec()),
            topics: self
                .topics
                .unwrap_or(vec![])
                .into_iter()
                .map(|t| t.to_opt())
                .collect(),
            trusted: false,
            space: Space::Ethereum,
        };

        match (&self.from_block, &self.to_block, &self.block_hash) {
            // block hash filter
            (None, None, Some(block_hash)) => {
                // check if `block_hash` is a valid pivot hash
                let epoch = consensus
                    .get_block_epoch_number(block_hash)
                    .ok_or(SelfError::InvalidParams(
                        "blockHash".to_string(),
                        "Unknown block".to_string(),
                    ))?;

                let hashes = consensus
                    .get_block_hashes_by_epoch(EpochNumber::Number(epoch))
                    .map_err(|_| {
                        SelfError::InvalidParams(
                            "blockHash".to_string(),
                            "Unknown block".to_string(),
                        )
                    })?;

                let pivot_hash = hashes.last().ok_or(
                    SelfError::InternalError("Inconsistent state".to_string()),
                )?;

                if block_hash != pivot_hash {
                    return Err(SelfError::InvalidParams(
                        "blockHash".to_string(),
                        "Unknown block".to_string(),
                    ));
                }

                // filter based on a single epoch
                Ok(PrimitiveFilter::EpochLogFilter {
                    from_epoch: EpochNumber::Number(epoch),
                    to_epoch: EpochNumber::Number(epoch),
                    params,
                })
            }

            // block number range filter
            // note: blocks in EVM space RPCs correspond to epochs
            (_, _, None) => {
                let from_epoch = match self.from_block {
                    // FIXME(thegaram): this is probably not consistent with eth
                    None => EpochNumber::LatestState,
                    Some(bn) => bn.try_into()?,
                };

                let to_epoch = match self.to_block {
                    None => EpochNumber::LatestState,
                    Some(bn) => bn.try_into()?,
                };

                Ok(PrimitiveFilter::EpochLogFilter {
                    from_epoch,
                    to_epoch,
                    params,
                })
            }

            // any other case is considered an error
            _ => {
                return Err(SelfError::InvalidParams(
                    "blockHash".to_string(),
                    format!("Filter must provide one of the following: (1) a block number range through `fromBlock` and `toBlock`, (2) a set of block hashes through `blockHash`")
                ));
            }
        }
    }
}

/// Results of the filter_changes RPC.
#[derive(Debug, PartialEq, Clone)]
pub enum FilterChanges {
    /// New logs.
    Logs(Vec<Log>),
    /// New hashes (block or transactions)
    Hashes(Vec<H256>),
    /// Empty result
    Empty,
}

impl Serialize for FilterChanges {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            FilterChanges::Logs(ref logs) => logs.serialize(s),
            FilterChanges::Hashes(ref hashes) => hashes.serialize(s),
            FilterChanges::Empty => (&[] as &[Value]).serialize(s),
        }
    }
}
