// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

pub mod block_retrieval;
pub mod block_retrieval_response;
pub mod consensus_msg;
pub mod epoch_change;
pub mod epoch_retrieval;
pub mod mempool_sync_msg;
pub mod proposal;
pub mod sync_info;
pub mod vote;

use super::HSB_PROTOCOL_VERSION;

use crate::{
    message::{
        GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId,
        RequestId, SetRequestId,
    },
    pos::{consensus::network::ConsensusMsg, mempool::network::MempoolSyncMsg},
};

use block_retrieval::BlockRetrievalRpcRequest;
use block_retrieval_response::BlockRetrievalRpcResponse;
use consensus_types::{
    epoch_retrieval::EpochRetrievalRequest, proposal_msg::ProposalMsg,
    sync_info::SyncInfo, vote_msg::VoteMsg,
};
use diem_types::epoch_change::EpochChangeProof;
use network::service::ProtocolVersion;

// FIXME: A temporary workaround by avoiding msg_id overlapping
// with SynchronizationProtocolHandler msg_id.
build_msgid! {
    PROPOSAL = 0x50
    VOTE = 0x51
    SYNC_INFO = 0x52
    BLOCK_RETRIEVAL = 0x53
    BLOCK_RETRIEVAL_RESPONSE = 0x54
    EPOCH_CHANGE = 0x55
    EPOCH_RETRIEVAL = 0x56
    CONSENSUS_MSG = 0x57
    MEMPOOL_SYNC_MSG = 0x58
    INVALID = 0xff
}

macro_rules! build_msg_impl_with_serde_serialization {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl GetMaybeRequestId for $name {}

        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    bcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id() as u8);
                encoded
            }
        }
    };
}

macro_rules! build_msg_impl_with_serde_serialization_generic {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl GetMaybeRequestId for $name {}

        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    bcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id() as u8);
                encoded
            }
        }
    };
}

macro_rules! build_msg_impl_with_request_id_and_serde_serialization {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    bcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id() as u8);
                encoded
            }
        }

        impl_request_id_methods!($name);
    };
}

build_msg_impl_with_serde_serialization_generic! {ProposalMsg, msgid::PROPOSAL, "ProposalMessage"}
mark_msg_version_bound!(
    ProposalMsg,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_serde_serialization_generic! {BlockRetrievalRpcResponse, msgid::BLOCK_RETRIEVAL_RESPONSE, "BlockRetrievalResponseMessage"}
mark_msg_version_bound!(
    BlockRetrievalRpcResponse,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_serde_serialization! {VoteMsg, msgid::VOTE, "VoteMessage"}
mark_msg_version_bound!(VoteMsg, HSB_PROTOCOL_VERSION, HSB_PROTOCOL_VERSION);
build_msg_impl_with_serde_serialization! {SyncInfo, msgid::SYNC_INFO, "SyncInfoMessage"}
mark_msg_version_bound!(SyncInfo, HSB_PROTOCOL_VERSION, HSB_PROTOCOL_VERSION);
build_msg_impl_with_serde_serialization! {EpochChangeProof, msgid::EPOCH_CHANGE, "EpochChangeMessage"}
mark_msg_version_bound!(
    EpochChangeProof,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_serde_serialization! {ConsensusMsg, msgid::CONSENSUS_MSG, "ConsensusMsg"}
mark_msg_version_bound!(
    ConsensusMsg,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_serde_serialization! {EpochRetrievalRequest, msgid::EPOCH_RETRIEVAL, "EpochRetrievalMessage"}
mark_msg_version_bound!(
    EpochRetrievalRequest,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_request_id_and_serde_serialization! {BlockRetrievalRpcRequest, msgid::BLOCK_RETRIEVAL, "BlockRetrievalMessage"}
mark_msg_version_bound!(
    BlockRetrievalRpcRequest,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
build_msg_impl_with_serde_serialization! {MempoolSyncMsg, msgid::MEMPOOL_SYNC_MSG, "MempoolSyncMsg"}
mark_msg_version_bound!(
    MempoolSyncMsg,
    HSB_PROTOCOL_VERSION,
    HSB_PROTOCOL_VERSION
);
