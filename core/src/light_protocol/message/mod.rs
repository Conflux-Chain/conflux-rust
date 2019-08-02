// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod message;
mod protocol;

pub use message::msgid;
pub use protocol::{
    GetStateEntry, GetStateRoot, StateEntry, StateRoot, Status,
};
