// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    request_manager::RequestMessage, Error, SynchronizationProtocolHandler,
};
use network::{NetworkContext, PeerId};

pub struct Context<'a> {
    pub io: &'a NetworkContext,
    pub peer: PeerId,
    pub manager: &'a SynchronizationProtocolHandler,
}

impl<'a> Context<'a> {
    pub fn match_request(
        &self, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.manager
            .request_manager
            .match_request(self.io, self.peer, request_id)
    }
}

// todo merge with Request and RequestContext!!!
pub trait Handleable {
    fn handle(self, ctx: &Context) -> Result<(), Error>;
}
