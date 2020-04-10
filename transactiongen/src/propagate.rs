// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use network::{
    node_table::NodeId, NetworkContext, NetworkProtocolHandler, NetworkService,
    ProtocolId,
};
use parking_lot::RwLock;
use priority_send_queue::SendQueuePriority;
use std::{collections::HashSet, sync::Arc, time::Duration};

const PROTOCOL_ID_DATA_PROPAGATION: ProtocolId = *b"dpp";
const PROTOCOL_VERSION_DATA_PROPAGATION: u8 = 1;

pub struct DataPropagation {
    interval: Duration,
    size: usize,
    peers: RwLock<HashSet<NodeId>>,
}

impl DataPropagation {
    pub fn new(interval_ms: u64, size: usize) -> Self {
        DataPropagation {
            interval: Duration::from_millis(interval_ms),
            size,
            peers: RwLock::new(HashSet::new()),
        }
    }

    pub fn register(
        dp: Arc<DataPropagation>, network: Arc<NetworkService>,
    ) -> Result<(), String> {
        if dp.interval == Duration::from_millis(0) || dp.size == 0 {
            return Ok(());
        }

        network
            .register_protocol(
                dp,
                PROTOCOL_ID_DATA_PROPAGATION,
                &[PROTOCOL_VERSION_DATA_PROPAGATION],
            )
            .map_err(|e| {
                format!("failed to register protocol DataPropagation: {:?}", e)
            })
    }
}

impl NetworkProtocolHandler for DataPropagation {
    fn initialize(&self, io: &dyn NetworkContext) {
        info!("DataPropagation.initialize: register timers");

        // FIXME: should use TX_TIMER instead of magic number 0.
        if let Err(e) = io.register_timer(0, self.interval) {
            error!(
                "DataPropagation.initialize: failed to register timer, {:?}",
                e
            );
        }
    }

    fn on_message(&self, _io: &dyn NetworkContext, peer: &NodeId, data: &[u8]) {
        if data.len() != self.size {
            error!("DataPropagation.on_message: received invalid data, len = {}, expected = {}", data.len(), self.size);
        }

        trace!(
            "DataPropagation.on_message: received data from peer {}",
            peer
        );
    }

    fn on_peer_connected(&self, _io: &dyn NetworkContext, peer: &NodeId) {
        debug!(
            "DataPropagation.on_peer_connected: new peer {} connected",
            peer
        );
        self.peers.write().insert(*peer);
    }

    fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: &NodeId) {
        debug!(
            "DataPropagation.on_peer_disconnected: peer {} disconnected",
            peer
        );
        self.peers.write().remove(peer);
    }

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken) {
        assert_eq!(timer, 0);

        for p in self.peers.read().iter() {
            if let Err(e) =
                io.send(p, vec![0; self.size], SendQueuePriority::Normal)
            {
                warn!(
                    "failed to propagate data to peer {}: {:?}",
                    p.clone(),
                    e
                );
            }

            trace!(
                "DataPropagation.on_timeout: sent data to peer {}",
                p.clone()
            );
        }
    }
}
