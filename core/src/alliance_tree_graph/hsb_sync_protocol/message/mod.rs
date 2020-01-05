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

use crate::message::{Message, MsgId};

use crate::hotstuff_types::{
    common::Payload, epoch_retrieval::EpochRetrievalRequest,
    proposal_msg::ProposalMsg, sync_info::SyncInfo, vote_msg::VoteMsg,
};
use block_retrieval::BlockRetrievalRpcRequest;
use block_retrieval_response::BlockRetrievalRpcResponse;
use libra_types::validator_change::ValidatorChangeProof;

build_msgid! {
    PROPOSAL = 0x00
    VOTE = 0x01
    SYNC_INFO = 0x02
    BLOCK_RETRIEVAL = 0x03
    BLOCK_RETRIEVAL_RESPONSE = 0x4
    EPOCH_CHANGE = 0x5
    EPOCH_RETRIEVAL = 0x6
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

build_msg_impl_with_serde_serialization_generic! {ProposalMsg, msgid::PROPOSAL, "ProposalMessage"}
build_msg_impl_with_serde_serialization_generic! {BlockRetrievalRpcResponse, msgid::BLOCK_RETRIEVAL_RESPONSE, "BlockRetrievalResponseMessage"}
build_msg_impl_with_serde_serialization! {VoteMsg, msgid::VOTE, "VoteMessage"}
build_msg_impl_with_serde_serialization! {SyncInfo, msgid::SYNC_INFO, "SyncInfoMessage"}
build_msg_impl_with_serde_serialization! {BlockRetrievalRpcRequest, msgid::BLOCK_RETRIEVAL, "BlockRetrievalMessage"}
build_msg_impl_with_serde_serialization! {ValidatorChangeProof, msgid::EPOCH_CHANGE, "EpochChangeMessage"}
build_msg_impl_with_serde_serialization! {EpochRetrievalRequest, msgid::EPOCH_RETRIEVAL, "EpochRetrievalMessage"}
