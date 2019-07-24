// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    sync::{
        request_manager::RequestManager, Error, ProtocolConfiguration,
        SynchronizationState,
    },
    SynchronizationGraph,
};
use network::{NetworkContext, PeerId};
use std::sync::Arc;

pub struct Context<'a> {
    pub peer: PeerId,
    pub syn: Arc<SynchronizationState>,
    pub graph: Arc<SynchronizationGraph>,
    pub request_manager: Arc<RequestManager>,
    pub protocol_config: &'a ProtocolConfiguration,
    pub io: &'a NetworkContext,
}

// todo merge with Request and RequestContext!!!
pub trait Handleable {
    fn handle(&self, ctx: &Context) -> Result<(), Error>;
}
