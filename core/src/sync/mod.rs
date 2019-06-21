// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod error;
pub mod request_manager;
mod synchronization_graph;
mod synchronization_protocol_handler;
mod synchronization_service;
mod synchronization_state;

pub use self::{
    error::{Error, ErrorKind},
    synchronization_graph::{
        BestInformation, SharedSynchronizationGraph, SyncGraphStatistics,
        SynchronizationGraph, SynchronizationGraphInner,
        SynchronizationGraphNode,
    },
    synchronization_protocol_handler::{
        ProtocolConfiguration, SynchronizationProtocolHandler,
        SYNCHRONIZATION_PROTOCOL_VERSION,
    },
    synchronization_service::{
        SharedSynchronizationService, SynchronizationService,
    },
    synchronization_state::{SynchronizationPeerState, SynchronizationState},
};

pub mod random {
    use rand;
    pub fn new() -> rand::ThreadRng { rand::thread_rng() }
}

pub mod msg_sender {
    use cfx_bytes::Bytes;
    use message::Message;
    use network::{
        throttling::THROTTLING_SERVICE, Error as NetworkError, NetworkContext,
        PeerId,
    };
    use priority_send_queue::SendQueuePriority;

    pub fn send_message(
        io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: SendQueuePriority,
    ) -> Result<(), NetworkError>
    {
        send_message_with_throttling(io, peer, msg, priority, false)
    }

    pub fn send_message_with_throttling(
        io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: SendQueuePriority, throttling_disabled: bool,
    ) -> Result<(), NetworkError>
    {
        if !throttling_disabled && msg.is_size_sensitive() {
            if let Err(e) = THROTTLING_SERVICE.read().check_throttling() {
                debug!("Throttling failure: {:?}", e);
                return Err(e);
            }
        }
        let mut raw = Bytes::new();
        raw.push(msg.msg_id().into());
        raw.extend(msg.rlp_bytes().iter());
        if let Err(e) = io.send(peer, raw, priority) {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };
        debug!(
            "Send message({}) to {:?}",
            msg.msg_id(),
            io.get_peer_node_id(peer)
        );
        Ok(())
    }

}
