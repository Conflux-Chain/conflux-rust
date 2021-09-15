// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use diem_types::{
    transaction::{TransactionPayload, TransactionStatus},
    vm_status::KeptVMStatus,
};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: H256,
    pub from: H256,
    pub block_hash: Option<H256>,
    pub number: U64,
    pub payload: Option<TransactionPayload>,
    pub status: Option<RpcTransactionStatus>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RpcTransactionStatus {
    Executed,
    Failed,
    Discard,
}

impl From<TransactionStatus> for RpcTransactionStatus {
    fn from(status: TransactionStatus) -> Self {
        match status {
            TransactionStatus::Discard(_) => RpcTransactionStatus::Discard,
            TransactionStatus::Keep(keep_status) => match keep_status {
                KeptVMStatus::Executed => RpcTransactionStatus::Executed,
                _ => RpcTransactionStatus::Failed,
            },
            TransactionStatus::Retry => RpcTransactionStatus::Failed,
        }
    }
}

impl From<KeptVMStatus> for RpcTransactionStatus {
    fn from(status: KeptVMStatus) -> Self {
        match status {
            KeptVMStatus::Executed => RpcTransactionStatus::Executed,
            _ => RpcTransactionStatus::Failed,
        }
    }
}
