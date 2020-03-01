// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod message;
pub mod request_manager;
pub mod sync_protocol;

use crate::network::ProtocolId;
pub const HSB_PROTOCOL_ID: ProtocolId = *b"hsb"; // HotStuff Synchronization Protocol
pub const HSB_PROTOCOL_VERSION: u8 = 1;
