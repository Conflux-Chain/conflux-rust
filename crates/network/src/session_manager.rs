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
use diem_types::validator_config::{ConsensusPublicKey, ConsensusVRFPublicKey};
use io::IoContext;
use log::debug;
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

/// An entry in `SessionManager::node_id_index`: the session's slab token and
/// its direction (`originated`).
///
/// `originated` is cached here so the simultaneous-dial tie-breaker in
/// `update_ingress_node_id` can read it without locking the `Session`. Kill
/// paths remove the entry (`remove_node_id_entry`) before marking the session
/// expired, so a present entry is not left pointing at an already-expired
/// session.
#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub token: usize,
    /// `true` = our outbound (egress); `false` = remote's inbound (ingress).
    pub originated: bool,
}

/// Outcome of `SessionManager::update_ingress_node_id`.
#[derive(Debug)]
pub enum UpdateIngressResult {
    Inserted,
    /// Caller should disconnect the old token.
    Replaced(usize),
    /// Caller should disconnect the new ingress it was about to
    /// register — the existing entry won the simultaneous-dial tie-break.
    DropNew,
}

/// Outcome of the simultaneous-dial tie-breaker for a (existing, new-ingress)
/// pair sharing the same remote `NodeId`.
#[derive(Debug, PartialEq, Eq)]
pub enum SimDialOutcome {
    KeepNew,
    KeepExisting,
}

/// Deterministically resolve a simultaneous dial: keep the connection where
/// the higher-`NodeId` peer is the dialer. Both sides compute the same
/// comparison over the same two `NodeId`s and converge on the same surviving
/// TCP connection.
pub fn simultaneous_dial_outcome(
    own_node_id: &NodeId, remote_node_id: &NodeId, existing_originated: bool,
) -> SimDialOutcome {
    if !existing_originated {
        // Existing is also an ingress (an older inbound from the same peer):
        // the fresher inbound replaces it.
        return SimDialOutcome::KeepNew;
    }
    if own_node_id < remote_node_id {
        SimDialOutcome::KeepNew
    } else {
        SimDialOutcome::KeepExisting
    }
}

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

    /// The local node's NodeId, used by `update_ingress_node_id` to
    /// compute the simultaneous-dial tie-break.
    own_node_id: NodeId,

    /// session indices. Each entry stores the slab token plus whether
    /// that session is egress (`originated = true`) or ingress
    /// (`originated = false`); the latter is consulted by the
    /// simultaneous-dial tie-breaker in `update_ingress_node_id`.
    node_id_index: RwLock<HashMap<NodeId, IndexEntry>>,
    ip_limit: RwLock<Box<dyn SessionIpLimit>>,
    tag_index: RwLock<SessionTagIndex>,
    /// pos public key
    pub self_pos_public_key:
        Option<(ConsensusPublicKey, ConsensusVRFPublicKey)>,
}

impl SessionManager {
    /// Create a new instance.
    pub fn new(
        offset: usize, capacity: usize, max_ingress_sessions: usize,
        own_node_id: NodeId, ip_limit_config: &SessionIpLimitConfig,
        self_pos_public_key: Option<(
            ConsensusPublicKey,
            ConsensusVRFPublicKey,
        )>,
    ) -> Self {
        SessionManager {
            sessions: RwLock::new(Slab::with_capacity(capacity)),
            offset,
            capacity,
            max_ingress_sessions,
            cur_ingress_sessions: AtomicUsize::new(0),
            own_node_id,
            node_id_index: RwLock::new(HashMap::new()),
            ip_limit: RwLock::new(new_session_ip_limit(ip_limit_config)),
            tag_index: Default::default(),
            self_pos_public_key,
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
        let token = self.node_id_index.read().get(node_id)?.token;
        sessions.get(token).cloned()
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
        self.node_id_index.read().get(id).map(|entry| entry.token)
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
    ) -> Result<usize, String> {
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
        let session = match Session::new(
            io,
            socket,
            address,
            id,
            PACKET_HEADER_VERSION,
            index,
            host,
            self.self_pos_public_key.clone(),
        ) {
            Err(e) => {
                debug!(
                    "SessionManager.create: leave on session creation failed"
                );
                return Err(format!("{:?}", e));
            }
            Ok(session) => session,
        };
        entry.insert(Arc::new(RwLock::new(session)));

        // update on creation succeeded
        if let Some(node_id) = id {
            // egress: id is Some at construction
            node_id_index.insert(
                node_id.clone(),
                IndexEntry {
                    token: index,
                    originated: true,
                },
            );
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
            // node_id_index was already cleared by `remove_node_id_entry`.

            assert!(self.ip_limit.write().remove(&session.address().ip()));

            if !session.metadata.originated {
                self.cur_ingress_sessions.fetch_sub(1, Ordering::Relaxed);
            }

            self.tag_index.write().remove(session.token());

            debug!("SessionManager.remove: session removed");
        }

        debug!("SessionManager.remove: leave");
    }

    /// Drop the reverse-index entry for `node_id` if it still points at
    /// `token`. Called early in a kill, before the session is marked expired.
    pub fn remove_node_id_entry(&self, node_id: &NodeId, token: usize) {
        let mut node_id_index = self.node_id_index.write();
        if let Some(entry) = node_id_index.get(node_id) {
            if entry.token == token {
                node_id_index.remove(node_id);
            }
        }
    }

    /// Update the node id index for an ingress session whose HELLO has
    /// just been processed and the remote `node_id` is now known.
    ///
    /// Returns:
    /// - `Err(_)` if the session at `idx` is no longer in the slab (the session
    ///   was killed concurrently — caller should drop the new ingress).
    /// - `Ok(Inserted)` — no prior entry for this `node_id`; the new ingress is
    ///   now in the index.
    /// - `Ok(Replaced(old_token))` — there was a prior entry; it has been
    ///   replaced. Caller should disconnect `old_token`.
    /// - `Ok(DropNew)` — there was a prior entry that won the simultaneous-dial
    ///   tie-break; the index is unchanged. Caller should disconnect the new
    ///   ingress (`idx`) it was about to register.
    pub fn update_ingress_node_id(
        &self, idx: usize, node_id: &NodeId,
    ) -> Result<UpdateIngressResult, String> {
        debug!("SessionManager.update_ingress_node_id: enter");

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

        let new_entry = IndexEntry {
            token: idx,
            originated: false,
        };

        if let Some(existing) = node_id_index.get(node_id).cloned() {
            if existing.token == idx {
                panic!("The same token already exists for the same node!!!");
            }
            let outcome = simultaneous_dial_outcome(
                &self.own_node_id,
                node_id,
                existing.originated,
            );
            match outcome {
                SimDialOutcome::KeepNew => {
                    node_id_index.insert(node_id.clone(), new_entry);
                    debug!("SessionManager.update_ingress_node_id: leave (replaced)");
                    Ok(UpdateIngressResult::Replaced(existing.token))
                }
                SimDialOutcome::KeepExisting => {
                    debug!("SessionManager.update_ingress_node_id: leave (drop new — tie-break lost)");
                    Ok(UpdateIngressResult::DropNew)
                }
            }
        } else {
            node_id_index.insert(node_id.clone(), new_entry);
            debug!("SessionManager.update_ingress_node_id: leave (inserted)");
            Ok(UpdateIngressResult::Inserted)
        }
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
    use crate::{
        node_table::NodeId,
        session_manager::{
            simultaneous_dial_outcome, SessionTagIndex, SimDialOutcome,
        },
    };

    #[test]
    fn simdial_two_nodes_converge_on_one_connection() {
        // Both sides of a simultaneous dial compute the same comparison
        // over the same two NodeIds and must converge on the same
        // surviving TCP connection — exactly one side keeps its existing
        // egress, the other side drops its own and accepts the new
        // ingress. Run both views of the same (A, B) pair and assert the
        // XOR property.
        let a = NodeId::from_low_u64_be(1);
        let b = NodeId::from_low_u64_be(2);

        // A's view: existing = A's egress to B (originated=true)
        let a_outcome = simultaneous_dial_outcome(&a, &b, true);
        // B's view: existing = B's egress to A (originated=true)
        let b_outcome = simultaneous_dial_outcome(&b, &a, true);

        let a_keeps = matches!(a_outcome, SimDialOutcome::KeepExisting);
        let b_keeps = matches!(b_outcome, SimDialOutcome::KeepExisting);
        assert!(
            a_keeps ^ b_keeps,
            "exactly one side must keep its egress; got a={:?} b={:?}",
            a_outcome,
            b_outcome
        );
    }

    #[test]
    fn simdial_outcome_cases() {
        let lo = NodeId::from_low_u64_be(1);
        let hi = NodeId::from_low_u64_be(2);

        // Ingress existing (originated = false): the fresher ingress wins.
        assert_eq!(
            simultaneous_dial_outcome(&lo, &hi, false),
            SimDialOutcome::KeepNew
        );
        assert_eq!(
            simultaneous_dial_outcome(&hi, &lo, false),
            SimDialOutcome::KeepNew
        );

        // Egress existing: the connection from the higher-NodeId peer wins.
        assert_eq!(
            simultaneous_dial_outcome(&lo, &hi, true),
            SimDialOutcome::KeepNew
        );
        assert_eq!(
            simultaneous_dial_outcome(&hi, &lo, true),
            SimDialOutcome::KeepExisting
        );
    }

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
