use cfx_rpc_primitives::Bytes;
use cfx_types::{Address, H256};
use serde::Deserialize;
use std::collections::HashMap;

use super::{transaction::TxPartIndices, AccountInfo};

/// State test indexed state result deserialization.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Test {
    pub expect_exception: Option<String>,

    /// Indexes
    pub indexes: TxPartIndices,
    /// Post state hash
    pub hash: H256,
    /// Post state
    #[serde(default)]
    pub post_state: HashMap<Address, AccountInfo>,

    /// Logs root
    pub logs: H256,

    /// Output state.
    ///
    /// Note: Not used.
    #[serde(default)]
    state: HashMap<Address, AccountInfo>,

    /// Tx bytes
    pub txbytes: Option<Bytes>,
}
