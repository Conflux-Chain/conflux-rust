// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod message;
mod protocol;

pub type RequestId = u64;

pub use self::{
    message::{Message, MsgId},
    protocol::{GetStateEntry, GetStateRoot, StateEntry, StateRoot},
};
