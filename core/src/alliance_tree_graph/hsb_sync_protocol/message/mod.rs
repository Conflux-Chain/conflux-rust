// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod proposal;

use crate::message::{Message, MsgId};

use proposal::ProposalMsgWithTransactions;

build_msgid! {
    PROPOSAL = 0x00
    VOTE = 0x01
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
