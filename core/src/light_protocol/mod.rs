// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod common;
mod config;
mod error;
mod handler;
mod message;
mod provider;
pub mod query_service;

use network::{service::ProtocolVersion, ProtocolId};

const LIGHT_PROTOCOL_ID: ProtocolId = *b"clp"; // Conflux Light Protocol
pub const LIGHT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(2);
/// Support at most this number of old versions.
const LIGHT_PROTOCOL_OLD_VERSIONS_TO_SUPPORT: u8 = 2;
/// The version to pass to Message for their lifetime declaration.
pub const LIGHT_PROTO_V1: ProtocolVersion = ProtocolVersion(1);
pub const LIGHT_PROTO_V2: ProtocolVersion = ProtocolVersion(2);

use error::handle as handle_error;

pub use config::Configuration as LightNodeConfiguration;
pub use error::{Error, ErrorKind};
pub use handler::Handler;
pub use provider::Provider;
pub use query_service::QueryService;
