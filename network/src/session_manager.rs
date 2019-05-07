// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    node_database::NodeIpLimit, node_table::NodeId,
    service::NetworkServiceInner, session::Session, NetworkIoMessage,
};
use io::IoContext;
use mio::net::TcpStream;
use parking_lot::RwLock;
use slab::{Slab, SlabIter};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

/// Session manager maintains all ingress and egress TCP connections.
/// It supports to limit the connections according to node IP policy.
pub struct SessionManager {
    sessions: Slab<Arc<RwLock<Session>>, usize>,
    node_id_index: HashMap<NodeId, usize>,
    ip_limit: NodeIpLimit,
}

impl SessionManager {
    pub fn new(offset: usize, capacity: usize, nodes_per_ip: usize) -> Self {
        SessionManager {
            sessions: Slab::new_starting_at(offset, capacity),
            node_id_index: HashMap::new(),
            ip_limit: NodeIpLimit::new(nodes_per_ip),
        }
    }

    pub fn count(&self) -> usize { self.sessions.count() }

    pub fn get(&self, idx: usize) -> Option<&Arc<RwLock<Session>>> {
        self.sessions.get(idx)
    }

    pub fn iter(&self) -> SlabIter<Arc<RwLock<Session>>, usize> {
        self.sessions.iter()
    }

    /// Retrieves the session count of handshakes, egress and ingress.
    pub fn stat(&self) -> (usize, usize, usize) {
        let mut handshakes = 0;
        let mut egress = 0;
        let mut ingress = 0;

        for s in self.sessions.iter() {
            match s.try_read() {
                Some(ref s) if s.is_ready() && s.metadata.originated => {
                    egress += 1
                }
                Some(ref s) if s.is_ready() && !s.metadata.originated => {
                    ingress += 1
                }
                _ => handshakes += 1,
            }
        }

        (handshakes, egress, ingress)
    }

    pub fn contains_node(&self, id: &NodeId) -> bool {
        self.node_id_index.contains_key(id)
    }

    /// Creates a new session with specified TCP socket. It is egress connection
    /// if the `id` is not `None`, otherwise it is ingress connection.
    pub fn create(
        &mut self, socket: TcpStream, address: SocketAddr, id: Option<&NodeId>,
        io: &IoContext<NetworkIoMessage>, host: &NetworkServiceInner,
    ) -> Result<usize, String>
    {
        // ensure the node id is unique if specified.
        if let Some(node_id) = id {
            if self.node_id_index.contains_key(node_id) {
                return Err(format!(
                    "session already exists, nodeId = {:?}",
                    node_id
                ));
            }
        }

        // validate against node IP policy.
        let ip = address.ip();
        if !self.ip_limit.is_ip_allowed(&ip) {
            return Err(format!(
                "IP policy limited, nodeId = {:?}, addr = {:?}",
                id, address
            ));
        }

        let index = match self.sessions.vacant_entry() {
            None => Err(String::from("Max sessions reached")),
            Some(entry) => {
                match Session::new(io, socket, address, id, entry.index(), host)
                {
                    Err(e) => Err(format!("{:?}", e)),
                    Ok(session) => {
                        Ok(entry.insert(Arc::new(RwLock::new(session))).index())
                    }
                }
            }
        }?;

        // update on creation succeeded
        if let Some(node_id) = id {
            self.node_id_index.insert(node_id.clone(), index);
        }

        self.ip_limit.on_add(ip);

        Ok(index)
    }

    pub fn remove(&mut self, session: &Session) {
        if self.sessions.remove(session.token()).is_some() {
            if let Some(node_id) = session.id() {
                self.node_id_index.remove(node_id);
            }

            self.ip_limit.on_delete(session.address().ip());
        }
    }

    pub fn update_ingress_node_id(
        &mut self, idx: usize, node_id: &NodeId,
    ) -> Result<(), String> {
        // ensure the node id is unique
        if let Some(cur_idx) = self.node_id_index.get(node_id) {
            return Err(format!("session already exists, node_id = {:?}, cur_idx = {}, new_idx = {}", node_id.clone(), *cur_idx, idx));
        }

        if !self.sessions.contains(idx) {
            return Err(format!(
                "session not found, index = {}, node_id = {:?}",
                idx,
                node_id.clone()
            ));
        }

        self.node_id_index.insert(node_id.clone(), idx);

        Ok(())
    }
}
