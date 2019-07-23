// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use network::{
    NetworkContext, NetworkProtocolHandler, NetworkService, PeerId, ProtocolId,
};
use parking_lot::RwLock;
use priority_send_queue::SendQueuePriority;
use std::{collections::HashSet, sync::Arc, time::Duration};

const PROTOCOL_ID_DATA_PROPAGATION: ProtocolId = *b"dpp";
const PROTOCOL_VERSION_DATA_PROPAGATION: u8 = 1;

pub struct DataPropagationService {
    handler: Arc<DataPropagationHandler>,
}

impl DataPropagationService {
    pub fn new(interval_ms: u64, size: usize) -> Self {
        let handler = Arc::new(DataPropagationHandler {
            interval: Duration::from_millis(interval_ms),
            size,
            peers: RwLock::new(HashSet::new()),
        });

        DataPropagationService { handler }
    }

    pub fn register(&self, network: Arc<NetworkService>) -> Result<(), String> {
        if self.handler.interval == Duration::from_millis(0)
            || self.handler.size == 0
        {
            return Ok(());
        }

        network
            .register_protocol(
                self.handler.clone(),
                PROTOCOL_ID_DATA_PROPAGATION,
                &[PROTOCOL_VERSION_DATA_PROPAGATION],
            )
            .map_err(|e| {
                format!("failed to register protocol DataPropagation: {:?}", e)
            })
    }
}

pub struct DataPropagationHandler {
    interval: Duration,
    size: usize,
    peers: RwLock<HashSet<PeerId>>,
}

impl NetworkProtocolHandler for DataPropagationHandler {
    fn initialize(&self, io: &NetworkContext) {
        info!("DataPropagationHandler.initialize: register timers");

        if let Err(e) = io.register_timer(0, self.interval) {
            error!(
                "DataPropagationHandler.initialize: failed to register timer, {:?}",
                e
            );
        }
    }

    fn on_message(&self, _io: &NetworkContext, peer: PeerId, data: &[u8]) {
        if data.len() != self.size {
            error!("DataPropagationHandler.on_message: received invalid data, len = {}, expected = {}", data.len(), self.size);
        }

        trace!(
            "DataPropagationHandler.on_message: received data from peer {}",
            peer
        );
    }

    fn on_peer_connected(&self, _io: &NetworkContext, peer: PeerId) {
        debug!(
            "DataPropagationHandler.on_peer_connected: new peer {} connected",
            peer
        );
        self.peers.write().insert(peer);
    }

    fn on_peer_disconnected(&self, _io: &NetworkContext, peer: PeerId) {
        debug!(
            "DataPropagationHandler.on_peer_disconnected: peer {} disconnected",
            peer
        );
        self.peers.write().remove(&peer);
    }

    fn on_timeout(&self, io: &NetworkContext, timer: TimerToken) {
        assert_eq!(timer, 0);

        for p in self.peers.read().iter() {
            if let Err(e) = io.send(
                p.clone(),
                vec![0; self.size],
                SendQueuePriority::Normal,
            ) {
                warn!(
                    "failed to propagate data to peer {}: {:?}",
                    p.clone(),
                    e
                );
            }

            trace!(
                "DataPropagationHandler.on_timeout: sent data to peer {}",
                p.clone()
            );
        }
    }
}
