// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use diem_types::{
    transaction::{TransactionPayload, TransactionStatus},
    vm_status::KeptVMStatus,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct Transaction {
    pub hash: H256,
    pub from: H256,
    pub block_hash: Option<H256>,
    pub block_number: Option<U64>,
    pub timestamp: Option<U64>,
    pub number: U64,
    pub payload: Option<TransactionPayload>,
    pub status: Option<RpcTransactionStatus>,
    pub tx_type: RpcTransactionType,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum RpcTransactionStatus {
    Executed,
    Failed,
    Discard,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum RpcTransactionType {
    BlockMetadata,
    Election,
    Retire,
    Register,
    UpdateVotingPower,
    PivotDecision,
    Dispute,
    Other,
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut struc = serializer.serialize_struct("Transaction", 9)?;
        struc.serialize_field("hash", &self.hash)?;
        struc.serialize_field("from", &self.from)?;
        struc.serialize_field("number", &self.number)?;
        struc.serialize_field("blockHash", &self.block_hash)?;
        struc.serialize_field("blockNumber", &self.block_number)?;
        struc.serialize_field("timestamp", &self.timestamp)?;
        struc.serialize_field("status", &self.status)?;
        struc.serialize_field("type", &self.tx_type)?;
        if self.payload.is_some() {
            match &self.payload.as_ref().unwrap() {
                TransactionPayload::Election(e) => {
                    struc.serialize_field("payload", e)?;
                }
                TransactionPayload::Retire(r) => {
                    struc.serialize_field("payload", r)?;
                }
                TransactionPayload::Register(r) => {
                    struc.serialize_field("payload", r)?;
                }
                TransactionPayload::UpdateVotingPower(u) => {
                    struc.serialize_field("payload", u)?;
                }
                TransactionPayload::PivotDecision(p) => {
                    struc.serialize_field("payload", p)?;
                }
                TransactionPayload::Dispute(d) => {
                    struc.serialize_field("payload", d)?;
                }
                _ => {}
            }
        } else {
            let empty: Option<TransactionPayload> = None;
            struc.serialize_field("payload", &empty)?
        }
        struc.end()
    }
}

pub fn tx_type(payload: TransactionPayload) -> RpcTransactionType {
    match payload {
        TransactionPayload::Election(_) => RpcTransactionType::Election,
        TransactionPayload::Retire(_) => RpcTransactionType::Retire,
        TransactionPayload::Register(_) => RpcTransactionType::Register,
        TransactionPayload::UpdateVotingPower(_) => {
            RpcTransactionType::UpdateVotingPower
        }
        TransactionPayload::PivotDecision(_) => {
            RpcTransactionType::PivotDecision
        }
        TransactionPayload::Dispute(_) => RpcTransactionType::Dispute,
        _ => RpcTransactionType::Other,
    }
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
