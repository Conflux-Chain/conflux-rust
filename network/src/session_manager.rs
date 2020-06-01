// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip::{new_session_ip_limit, SessionIpLimit, SessionIpLimitConfig},
    node_table::NodeId,
    service::NetworkServiceInner,
    session::{Session, PACKET_HEADER_VERSION},
    NetworkIoMessage,
};
use io::IoContext;
use mio::net::TcpStream;
use parking_lot::RwLock;
use slab::Slab;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Session manager maintains all ingress and egress TCP connections in thread
/// safe manner.
///
/// It supports to limit the number of connections according to the node IP
/// policy, including limitations for a single IP address and different types of
/// subnet (e.g. subnet C, 192.168.1.xxx/24).
///
/// The session manager also limits the maximum number of incoming TCP
/// connections, so as to establish some trusted outgoing connections.
pub struct SessionManager {
    sessions: RwLock<Slab<Arc<RwLock<Session>>>>,
    capacity: usize,

    #[allow(unused)]
    /// FIXME It's not used because currently it's always 0.
    /// Token id offset.
    offset: usize,

    /// used to limit the ingress sessions.
    max_ingress_sessions: usize,
    cur_ingress_sessions: AtomicUsize,

    /// session indices
    node_id_index: RwLock<HashMap<NodeId, usize>>,
    ip_limit: RwLock<Box<dyn SessionIpLimit>>,
    tag_index: RwLock<SessionTagIndex>,
}

impl SessionManager {
    /// Create a new instance.
    pub fn new(
        offset: usize, capacity: usize, max_ingress_sessions: usize,
        ip_limit_config: &SessionIpLimitConfig,
    ) -> Self
    {
        SessionManager {
            sessions: RwLock::new(Slab::with_capacity(capacity)),
            offset,
            capacity,
            max_ingress_sessions,
            cur_ingress_sessions: AtomicUsize::new(0),
            node_id_index: RwLock::new(HashMap::new()),
            ip_limit: RwLock::new(new_session_ip_limit(ip_limit_config)),
            tag_index: Default::default(),
        }
    }

    /// Get the number of sessions in `SessionManager`.
    pub fn count(&self) -> usize { self.sessions.read().len() }

    /// Get the session of specified index.
    pub fn get(&self, idx: usize) -> Option<Arc<RwLock<Session>>> {
        self.sessions.read().get(idx).cloned()
    }

    /// Get the session of specified node id.
    pub fn get_by_id(&self, node_id: &NodeId) -> Option<Arc<RwLock<Session>>> {
        let sessions = self.sessions.read();
        let idx = *self.node_id_index.read().get(node_id)?;
        sessions.get(idx).cloned()
    }

    /// Get all the sessions in `SessionManager`.
    pub fn all(&self) -> Vec<Arc<RwLock<Session>>> {
        self.sessions
            .read()
            .iter()
            .map(|(_, s)| s.clone())
            .collect()
    }

    /// Add tag for the session of specified index, so as to support session
    /// filtering by tags. E.g. get the number of sessions from archive
    /// nodes.
    pub fn add_tag(&self, idx: usize, key: String, value: String) {
        self.tag_index.write().add(idx, key, value);
    }

    /// Get the number of sessions with specified tag.
    pub fn count_with_tag(&self, key: &String, value: &String) -> usize {
        self.tag_index.read().count_with_tag(key, value)
    }

    /// Retrieves the session count of handshakes, egress and ingress.
    pub fn stat(&self) -> (usize, usize, usize) {
        let mut handshakes = 0;
        let mut egress = 0;
        let mut ingress = 0;

        for (_, s) in self.sessions.read().iter() {
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

    /// Check the session existence for the specified node id.
    pub fn contains_node(&self, id: &NodeId) -> bool {
        self.node_id_index.read().contains_key(id)
    }

    /// Get the session index by node id.
    pub fn get_index_by_id(&self, id: &NodeId) -> Option<usize> {
        self.node_id_index.read().get(id).cloned()
    }

    /// Check if the specified IP address is allowed to create a new session.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.ip_limit.read().is_allowed(ip)
    }

    /// Creates a new session with specified TCP socket. It is egress connection
    /// if the `id` is not `None`, otherwise it is ingress connection.
    pub fn create(
        &self, socket: TcpStream, address: SocketAddr, id: Option<&NodeId>,
        io: &IoContext<NetworkIoMessage>, host: &NetworkServiceInner,
    ) -> Result<usize, String>
    {
        debug!(
            "SessionManager.create: enter, address = {:?}, id = {:?}",
            address, id
        );

        let mut sessions = self.sessions.write();
        let mut node_id_index = self.node_id_index.write();
        let mut ip_limit = self.ip_limit.write();

        // limits ingress sessions whose node id is `None`.
        let ingress = self.cur_ingress_sessions.load(Ordering::Relaxed);
        if id.is_none() && ingress >= self.max_ingress_sessions {
            debug!("SessionManager.create: leave on maximum ingress sessions reached");
            return Err(format!(
                "maximum ingress sessions reached, current = {}, max = {}",
                ingress, self.max_ingress_sessions
            ));
        }

        // ensure the node id is unique if specified.
        if let Some(node_id) = id {
            if node_id_index.contains_key(node_id) {
                debug!(
                    "SessionManager.create: leave on node_id already exists"
                );
                return Err(format!(
                    "session already exists, nodeId = {:?}",
                    node_id
                ));
            }
        }

        // validate against node IP policy.
        let ip = address.ip();
        if !ip_limit.is_allowed(&ip) {
            debug!("SessionManager.create: leave on IP policy limited");
            return Err(format!(
                "IP policy limited, nodeId = {:?}, addr = {:?}",
                id, address
            ));
        }

        if sessions.len() >= self.capacity {
            debug!("SessionManager.create: leave on MAX sessions reached");
            return Err(String::from("Max sessions reached"));
        }
        let entry = sessions.vacant_entry();
        let index = entry.key();
        match Session::new(
            io,
            socket,
            address,
            id,
            PACKET_HEADER_VERSION,
            index,
            host,
        ) {
            Err(e) => {
                debug!(
                    "SessionManager.create: leave on session creation failed"
                );
                return Err(format!("{:?}", e));
            }
            Ok(session) => entry.insert(Arc::new(RwLock::new(session))),
        };

        // update on creation succeeded
        if let Some(node_id) = id {
            node_id_index.insert(node_id.clone(), index);
        }

        assert!(ip_limit.add(ip));

        if id.is_none() {
            self.cur_ingress_sessions.fetch_add(1, Ordering::Relaxed);
        }

        debug!("SessionManager.create: leave");

        Ok(index)
    }

    /// Remove a session from the `SessionManager`.
    pub fn remove(&self, session: &Session) {
        debug!("SessionManager.remove: enter");

        let mut sessions = self.sessions.write();

        // TODO This check can be removed?
        if sessions.contains(session.token()) {
            sessions.remove(session.token());
            if let Some(node_id) = session.id() {
                let mut node_id_index = self.node_id_index.write();
                if let Some(token) = node_id_index.get(node_id) {
                    if *token == session.token() {
                        node_id_index.remove(node_id);
                    }
                }
            }

            assert!(self.ip_limit.write().remove(&session.address().ip()));

            if !session.metadata.originated {
                self.cur_ingress_sessions.fetch_sub(1, Ordering::Relaxed);
            }

            self.tag_index.write().remove(session.token());

            debug!("SessionManager.remove: session removed");
        }

        debug!("SessionManager.remove: leave");
    }

    /// Update the node id index for ingress session.
    /// Return error if the session index does not exist, or the node id already
    /// in use by other session.
    /// Return optional to-be-disconnected token if no error happens.
    pub fn update_ingress_node_id(
        &self, idx: usize, node_id: &NodeId,
    ) -> Result<Option<usize>, String> {
        debug!("SessionManager.update_ingress_node_id: enter");
        let mut token_to_disconnect = None;

        let sessions = self.sessions.read();
        let mut node_id_index = self.node_id_index.write();

        if !sessions.contains(idx) {
            debug!("SessionManager.update_ingress_node_id: leave on session not found");
            return Err(format!(
                "session not found, index = {}, node_id = {:?}",
                idx,
                node_id.clone()
            ));
        }

        // ensure the node id is unique
        if let Some(cur_idx) = node_id_index.get(node_id) {
            debug!("SessionManager.update_ingress_node_id: leave on node_id already exists");
            if *cur_idx != idx {
                token_to_disconnect = Some(*cur_idx);
            } else {
                panic!("The same token already exists for the same node!!!");
            }
        }

        node_id_index.insert(node_id.clone(), idx);

        debug!("SessionManager.update_ingress_node_id: leave");

        Ok(token_to_disconnect)
    }
}

#[derive(Default)]
struct SessionTagIndex {
    tag_key_to_value_to_sessions:
        HashMap<String, HashMap<String, HashSet<usize>>>,
    session_to_tags: HashMap<usize, HashMap<String, String>>,
}

impl SessionTagIndex {
    fn remove(&mut self, idx: usize) -> Option<()> {
        let tags = self.session_to_tags.remove(&idx)?;

        for (key, value) in tags {
            assert!(self.remove_with_tag(idx, &key, &value).is_some());
        }

        Some(())
    }

    fn remove_with_tag(
        &mut self, idx: usize, key: &String, value: &String,
    ) -> Option<()> {
        let value_to_sessions =
            self.tag_key_to_value_to_sessions.get_mut(key)?;
        let sessions = value_to_sessions.get_mut(value)?;

        if !sessions.remove(&idx) {
            return None;
        }

        if sessions.is_empty() {
            value_to_sessions.remove(value);
        }

        if value_to_sessions.is_empty() {
            self.tag_key_to_value_to_sessions.remove(key);
        }

        Some(())
    }

    fn add(&mut self, idx: usize, key: String, value: String) {
        let removed_tag_value = self
            .session_to_tags
            .entry(idx)
            .or_insert_with(Default::default)
            .insert(key.clone(), value.clone());

        if let Some(removed_tag_value) = removed_tag_value {
            if &removed_tag_value == &value {
                return;
            }

            assert!(self
                .remove_with_tag(idx, &key, &removed_tag_value)
                .is_some());
        }

        assert!(self
            .tag_key_to_value_to_sessions
            .entry(key)
            .or_insert_with(Default::default)
            .entry(value)
            .or_insert_with(Default::default)
            .insert(idx));
    }

    fn count_with_tag(&self, key: &String, value: &String) -> usize {
        match self.tag_key_to_value_to_sessions.get(key) {
            Some(value_to_sessions) => match value_to_sessions.get(value) {
                Some(sessions) => sessions.len(),
                None => 0,
            },
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::session_manager::SessionTagIndex;

    #[test]
    fn test_tag_index() {
        let mut index = SessionTagIndex::default();

        let k1: String = "k1".into();
        let k2: String = "k2".into();
        let v1: String = "v1".into();
        let v2: String = "v2".into();

        // empty
        assert_eq!(index.count_with_tag(&k1, &v1), 0);

        // add session 5 with tag <k1, v1>
        index.add(5, k1.clone(), v1.clone());
        assert_eq!(index.count_with_tag(&k1, &v1), 1);

        // duplicate
        index.add(5, k1.clone(), v1.clone());
        assert_eq!(index.count_with_tag(&k1, &v1), 1);

        // add session 8 with tag <k1, v1>
        index.add(8, k1.clone(), v1.clone());
        assert_eq!(index.count_with_tag(&k1, &v1), 2);

        // update session 5, change tag <k1, v1> to <k1, v2>
        index.add(5, k1.clone(), v2.clone());
        assert_eq!(index.count_with_tag(&k1, &v1), 1);
        assert_eq!(index.count_with_tag(&k1, &v2), 1);

        // update session 8, add tag <k2, v1>
        index.add(8, k2.clone(), v1.clone());
        assert_eq!(index.count_with_tag(&k1, &v1), 1);
        assert_eq!(index.count_with_tag(&k1, &v2), 1);
        assert_eq!(index.count_with_tag(&k2, &v1), 1);

        // remove session 5
        index.remove(5);
        assert_eq!(index.count_with_tag(&k1, &v1), 1);
        assert_eq!(index.count_with_tag(&k1, &v2), 0);
        assert_eq!(index.count_with_tag(&k2, &v1), 1);

        // remove session 8
        index.remove(8);
        assert_eq!(index.count_with_tag(&k1, &v1), 0);
        assert_eq!(index.count_with_tag(&k1, &v2), 0);
        assert_eq!(index.count_with_tag(&k2, &v1), 0);
    }
}
