// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Pub-Sub types.

use super::{EthRpcLogFilter, Header, Log};
use cfx_types::H256;
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
}

/// Subscription kind.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Params {
    /// No parameters passed.
    None,
    /// Log parameters.
    Logs(EthRpcLogFilter),
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
        from_value(v.clone()).map(Params::Logs).map_err(|e| {
            D::Error::custom(format!("Invalid Pub-Sub parameters: {}", e))
        })
    }
}
