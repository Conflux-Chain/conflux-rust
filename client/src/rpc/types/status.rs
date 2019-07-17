// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::H256;
use serde_derive::Serialize;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// Hash of the block
    pub best_hash: H256,
    /// The number of epochs
    pub epoch_number: u64,
    /// The number of blocks
    pub block_number: usize,
    /// The number of pending transactions
    pub pending_tx_number: usize,
}
