// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::Message,
    sync::{
        request_manager::RequestMessage, Error, SynchronizationProtocolHandler,
    },
};
use network::{node_table::NodeId, NetworkContext};

pub struct Context<'a> {
    pub io: &'a dyn NetworkContext,
    pub node_id: NodeId,
    pub manager: &'a SynchronizationProtocolHandler,
}

impl<'a> Context<'a> {
    pub fn match_request(
        &self, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.manager
            .request_manager
            .match_request(&self.node_id, request_id)
    }

    pub fn send_response(&self, response: &dyn Message) -> Result<(), Error> {
        response.send(self.io, &self.node_id)?;
        Ok(())
    }

    pub fn insert_peer_node_tag(&self, peer: NodeId, key: &str, value: &str) {
        self.io.insert_peer_node_tag(peer, key, value)
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }
}

// todo merge with Request and RequestContext!!!
pub trait Handleable {
    fn handle(self, ctx: &Context) -> Result<(), Error>;
}
