// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Pub-Sub types.

use crate::rpc::types::{CfxRpcLogFilter, Header, Log};
use cfx_types::{H256, U256};
use serde::{de::Error, Deserialize, Deserializer, Serialize};
use serde_json::{from_value, Value};

/// Subscription result.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged, rename_all = "camelCase")]
// NOTE: rename_all does not apply to enum member fields
// see: https://github.com/serde-rs/serde/issues/1061
pub enum Result {
    /// New block header.
    Header(Header),

    /// Log
    Log(Log),

    /// Transaction hash
    TransactionHash(H256),

    /// Epoch
    #[serde(rename_all = "camelCase")]
    Epoch {
        epoch_number: U256,
        epoch_hashes_ordered: Vec<H256>,
    },

    /// Chain reorg
    #[serde(rename_all = "camelCase")]
    ChainReorg { revert_to: U256 },
}

/// Subscription kind.
#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    /// New block headers subscription.
    NewHeads,
    /// Logs subscription.
    Logs,
    /// New Pending Transactions subscription.
    NewPendingTransactions,
    /// Node syncing status subscription.
    Syncing,
    /// Epoch
    Epochs,
}

/// Subscription epoch.
#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionEpoch {
    /// Latest epoch available.
    LatestMined,
    /// Latest epoch executed.
    LatestState,
}

/// Subscription kind.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Params {
    /// No parameters passed.
    None,
    /// Log parameters.
    Logs(CfxRpcLogFilter),
    /// Epoch parameters.
    Epochs(SubscriptionEpoch),
}

impl Default for Params {
    fn default() -> Self { Params::None }
}

impl<'a> Deserialize<'a> for Params {
    fn deserialize<D>(
        deserializer: D,
    ) -> ::std::result::Result<Params, D::Error>
    where D: Deserializer<'a> {
        let v: Value = Deserialize::deserialize(deserializer)?;

        if v.is_null() {
            return Ok(Params::None);
        }

        // try to interpret as a log filter
        if let Ok(v) = from_value(v.clone()).map(Params::Logs) {
            return Ok(v);
        }

        // otherwise, interpret as epoch
        from_value(v).map(Params::Epochs).map_err(|e| {
            D::Error::custom(format!("Invalid Pub-Sub parameters: {}", e))
        })
    }
}
