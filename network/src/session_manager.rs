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
use slab::Slab;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

/// Session manager maintains all ingress and egress TCP connections in thread
/// safe manner. It supports to limit the connections according to node IP
/// policy.
pub struct SessionManager {
    sessions: RwLock<Slab<Arc<RwLock<Session>>, usize>>,
    node_id_index: RwLock<HashMap<NodeId, usize>>,
    ip_limit: RwLock<NodeIpLimit>,
}

impl SessionManager {
    pub fn new(offset: usize, capacity: usize, nodes_per_ip: usize) -> Self {
        SessionManager {
            sessions: RwLock::new(Slab::new_starting_at(offset, capacity)),
            node_id_index: RwLock::new(HashMap::new()),
            ip_limit: RwLock::new(NodeIpLimit::new(nodes_per_ip)),
        }
    }

    pub fn count(&self) -> usize { self.sessions.read().count() }

    pub fn get(&self, idx: usize) -> Option<Arc<RwLock<Session>>> {
        self.sessions.read().get(idx).cloned()
    }

    pub fn visit<F>(&self, mut visitor: F)
    where F: FnMut(&Arc<RwLock<Session>>) {
        for session in self.sessions.read().iter() {
            visitor(session);
        }
    }

    /// Retrieves the session count of handshakes, egress and ingress.
    pub fn stat(&self) -> (usize, usize, usize) {
        let mut handshakes = 0;
        let mut egress = 0;
        let mut ingress = 0;

        for s in self.sessions.read().iter() {
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
        self.node_id_index.read().contains_key(id)
    }

    /// Creates a new session with specified TCP socket. It is egress connection
    /// if the `id` is not `None`, otherwise it is ingress connection.
    pub fn create(
        &self, socket: TcpStream, address: SocketAddr, id: Option<&NodeId>,
        io: &IoContext<NetworkIoMessage>, host: &NetworkServiceInner,
    ) -> Result<usize, String>
    {
        let mut sessions = self.sessions.write();
        let mut node_id_index = self.node_id_index.write();
        let mut ip_limit = self.ip_limit.write();

        // ensure the node id is unique if specified.
        if let Some(node_id) = id {
            if node_id_index.contains_key(node_id) {
                return Err(format!(
                    "session already exists, nodeId = {:?}",
                    node_id
                ));
            }
        }

        // validate against node IP policy.
        let ip = address.ip();
        if !ip_limit.is_ip_allowed(&ip) {
            return Err(format!(
                "IP policy limited, nodeId = {:?}, addr = {:?}",
                id, address
            ));
        }

        let index = match sessions.vacant_entry() {
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
            node_id_index.insert(node_id.clone(), index);
        }

        ip_limit.on_add(ip);

        Ok(index)
    }

    /// Removes an expired session with specified `idx`.
    pub fn remove(&self, idx: usize) -> Option<Arc<RwLock<Session>>> {
        let mut sessions = self.sessions.write();
        let session = sessions.get(idx).cloned()?;
        let sess = session.write();

        if !sess.expired() {
            return None;
        }

        let removed = sessions.remove(idx)?;

        if let Some(node_id) = sess.id() {
            self.node_id_index.write().remove(node_id);
        }

        self.ip_limit.write().on_delete(sess.address().ip());

        Some(removed)
    }

    pub fn update_ingress_node_id(
        &self, idx: usize, node_id: &NodeId,
    ) -> Result<(), String> {
        let sessions = self.sessions.read();
        let mut node_id_index = self.node_id_index.write();

        if !sessions.contains(idx) {
            return Err(format!(
                "session not found, index = {}, node_id = {:?}",
                idx,
                node_id.clone()
            ));
        }

        // ensure the node id is unique
        if let Some(cur_idx) = node_id_index.get(node_id) {
            return Err(format!("session already exists, node_id = {:?}, cur_idx = {}, new_idx = {}", node_id.clone(), *cur_idx, idx));
        }

        node_id_index.insert(node_id.clone(), idx);

        Ok(())
    }
}
