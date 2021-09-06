// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use diem_types::transaction::{TransactionPayload, TransactionStatus};
use serde_derive::Serialize;

// TODO event
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: H256,
    pub from: H256,
    pub version: U64,
    pub payload: TransactionPayload,
    pub status: TransactionStatus,
}
