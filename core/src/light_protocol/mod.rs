// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod error;
mod handler;
mod message;
mod query_provider;
mod query_service;

use crate::network::ProtocolId;
const LIGHT_PROTOCOL_ID: ProtocolId = *b"clp"; // Conflux Light Protocol
const LIGHT_PROTOCOL_VERSION: u8 = 1;

use self::error::{handle as handle_error, Error, ErrorKind};

pub use self::{
    handler::Handler, query_provider::QueryProvider,
    query_service::QueryService,
};
