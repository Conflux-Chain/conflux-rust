// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

pub mod message;
pub mod network_event;
pub mod network_sender;
pub mod request_manager;
pub mod sync_protocol;

use network::{service::ProtocolVersion, ProtocolId};

pub const HSB_PROTOCOL_ID: ProtocolId = *b"hsb"; // HotStuff Synchronization Protocol
pub const HSB_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);
