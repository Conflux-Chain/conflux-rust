// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod proposal;
pub mod sync_info;
pub mod vote;

use crate::message::{Message, MsgId};

use crate::hotstuff_types::{sync_info::SyncInfo, vote_msg::VoteMsg};
use proposal::ProposalMsgWithTransactions;

build_msgid! {
    PROPOSAL = 0x00
    VOTE = 0x01
    SYNC_INFO = 0x02
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

build_msg_impl_with_serde_serialization! {ProposalMsgWithTransactions, msgid::PROPOSAL, "ProposalMessage"}
build_msg_impl_with_serde_serialization! {VoteMsg, msgid::VOTE, "VoteMessage"}
build_msg_impl_with_serde_serialization! {SyncInfo, msgid::SYNC_INFO, "SyncInfoMessage"}
