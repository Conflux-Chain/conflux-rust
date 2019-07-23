// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::Message, msg_sender::send_message,
    request_manager::RequestManager, Error, SynchronizationGraph,
};
use network::{NetworkContext, PeerId};
use std::sync::Arc;

pub struct RequestContext<'a> {
    pub peer: PeerId,
    pub io: &'a NetworkContext,
    pub graph: Arc<SynchronizationGraph>,
    pub request_manager: Arc<RequestManager>,
}

impl<'a> RequestContext<'a> {
    pub fn send_response(&self, response: &Message) -> Result<(), Error> {
        send_message(self.io, self.peer, response, response.priority())?;
        Ok(())
    }
}

pub trait Request {
    fn handle(&self, context: &RequestContext) -> Result<(), Error>;
}
