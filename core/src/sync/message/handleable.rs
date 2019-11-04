// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::Message,
    sync::{
        request_manager::RequestMessage, Error, SynchronizationProtocolHandler,
    },
};
use cfx_types::H256;
use network::{NetworkContext, PeerId};
use primitives::StateRoot;

pub struct Context<'a> {
    pub io: &'a dyn NetworkContext,
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

    pub fn send_response(&self, response: &dyn Message) -> Result<(), Error> {
        response.send(self.io, self.peer)?;
        Ok(())
    }

    pub fn must_get_state_root(&self, checkpoint: &H256) -> StateRoot {
        match self.manager.graph.data_man.block_header_by_hash(checkpoint) {
            Some(header) => header
                .deferred_state_root_with_aux_info()
                .state_root
                .clone(),
            None => {
                error!(
                    "failed to find the state root of checkpoint {:?}",
                    checkpoint
                );
                panic!(
                    "Cannot find block header of checkpoint to sync snapshot"
                );
            }
        }
    }
}

// todo merge with Request and RequestContext!!!
pub trait Handleable {
    fn handle(self, ctx: &Context) -> Result<(), Error>;
}
