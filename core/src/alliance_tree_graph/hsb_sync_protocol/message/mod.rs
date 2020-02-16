// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod block_retrieval;
pub mod block_retrieval_response;
pub mod epoch_change;
pub mod epoch_retrieval;
pub mod proposal;
pub mod sync_info;
pub mod vote;

use crate::message::{Message, MsgId, RequestId};

use crate::alliance_tree_graph::bft::consensus::consensus_types::{
    common::Payload, epoch_retrieval::EpochRetrievalRequest,
    proposal_msg::ProposalMsg, sync_info::SyncInfo, vote_msg::VoteMsg,
};
use block_retrieval::BlockRetrievalRpcRequest;
use block_retrieval_response::BlockRetrievalRpcResponse;
use libra_types::validator_change::ValidatorChangeProof;

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
    INVALID = 0xff
}

macro_rules! build_msg_impl_with_serde_serialization {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    lcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id());
                encoded
            }
        }
    };
}

macro_rules! build_msg_impl_with_serde_serialization_generic {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl<T: Payload> Message for $name<T> {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    lcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id());
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

            fn get_request_id(&self) -> Option<RequestId> {
                Some(self.request_id)
            }

            fn set_request_id(&mut self, id: RequestId) {
                self.request_id = id;
            }

            fn encode(&self) -> Vec<u8> {
                let mut encoded =
                    lcs::to_bytes(self).expect("Failed to serialize.");
                encoded.push(self.msg_id());
                encoded
            }
        }
    };
}

build_msg_impl_with_serde_serialization_generic! {ProposalMsg, msgid::PROPOSAL, "ProposalMessage"}
build_msg_impl_with_serde_serialization_generic! {BlockRetrievalRpcResponse, msgid::BLOCK_RETRIEVAL_RESPONSE, "BlockRetrievalResponseMessage"}
build_msg_impl_with_serde_serialization! {VoteMsg, msgid::VOTE, "VoteMessage"}
build_msg_impl_with_serde_serialization! {SyncInfo, msgid::SYNC_INFO, "SyncInfoMessage"}
build_msg_impl_with_serde_serialization! {ValidatorChangeProof, msgid::EPOCH_CHANGE, "EpochChangeMessage"}
build_msg_impl_with_serde_serialization! {EpochRetrievalRequest, msgid::EPOCH_RETRIEVAL, "EpochRetrievalMessage"}
build_msg_impl_with_request_id_and_serde_serialization! {BlockRetrievalRpcRequest, msgid::BLOCK_RETRIEVAL, "BlockRetrievalMessage"}
