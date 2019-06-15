// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip_limit::NodeIpLimit,
    node_table::{Node, NodeContact, NodeEntry, NodeId, NodeTable},
    IpFilter,
};
use io::StreamToken;
use std::time::{Duration, SystemTime};

/// Node database maintains all P2P nodes in trusted and untrusted node tables,
/// and support to limit the number of nodes for the same IP address.
pub struct NodeDatabase {
    trusted_nodes: NodeTable,
    untrusted_nodes: NodeTable,
    ip_limit: NodeIpLimit,
}

impl NodeDatabase {
    pub fn new(path: Option<String>, nodes_per_ip: usize) -> Self {
        let trusted_nodes = NodeTable::new(path.clone(), true);
        let untrusted_nodes = NodeTable::new(path.clone(), false);
        let mut ip_limit = NodeIpLimit::new(nodes_per_ip);

        NodeDatabase::init(&mut ip_limit, &trusted_nodes);
        NodeDatabase::init(&mut ip_limit, &untrusted_nodes);

        NodeDatabase {
            trusted_nodes,
            untrusted_nodes,
            ip_limit,
        }
    }

    /// add or update a node with the specified `entry` and `stream_token`.
    pub fn insert_with_token(
        &mut self, entry: NodeEntry, stream_token: StreamToken,
    ) {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(
                &entry.id,
                true,
                Some(stream_token),
            );
            return;
        }

        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());
        node.last_connected = Some(NodeContact::success());
        node.stream_token = Some(stream_token);

        match self.pre_insert_untrusted(&node) {
            InsertResult::Added
            | InsertResult::Updated
            | InsertResult::IpUpdated => {
                self.untrusted_nodes.add_node(node, false);
            }
            InsertResult::IpLimited => {
                self.replace(node, false);
            }
        }
    }

    /// Add or update a node with the specified `entry`.
    pub fn insert(&mut self, entry: NodeEntry) {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(&entry.id, false, None);
            return;
        }

        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        match self.pre_insert_untrusted(&node) {
            InsertResult::Added | InsertResult::Updated => {
                self.untrusted_nodes.update_last_contact(node);
            }
            InsertResult::IpUpdated => {
                if let Some(old_node) =
                    self.untrusted_nodes.remove_with_id(&entry.id)
                {
                    node.last_connected = old_node.last_connected;
                    node.stream_token = old_node.stream_token;
                }

                self.untrusted_nodes.update_last_contact(node);
            }
            InsertResult::IpLimited => {
                self.replace(node, false);
            }
        }
    }

    /// Add or update a node with the specified `entry`, and promote the node to
    /// trusted if it is untrusted.
    pub fn insert_with_promotion(&mut self, entry: NodeEntry) {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(&entry.id, false, None);
            return;
        }

        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        match self.pre_insert_untrusted(&node) {
            InsertResult::Added
            | InsertResult::Updated
            | InsertResult::IpUpdated => {
                if let Some(old_node) =
                    self.untrusted_nodes.remove_with_id(&entry.id)
                {
                    node.last_connected = old_node.last_connected;
                    node.stream_token = old_node.stream_token;
                }

                self.trusted_nodes.add_node(node, false);
            }
            InsertResult::IpLimited => {
                self.replace(node, true);
            }
        }
    }

    /// Add a new trusted node if not exists, or promote an existing untrusted
    /// node.
    pub fn insert_trusted(&mut self, entry: NodeEntry) {
        if self.trusted_nodes.contains(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id.clone(), entry.endpoint.clone());

        match self.pre_insert_untrusted(&node) {
            InsertResult::Added
            | InsertResult::Updated
            | InsertResult::IpUpdated => {
                if let Some(old_node) =
                    self.untrusted_nodes.remove_with_id(&entry.id)
                {
                    node.last_contact = old_node.last_contact;
                    node.last_connected = old_node.last_connected;
                    node.stream_token = old_node.stream_token;
                }

                self.trusted_nodes.add_node(node, false);
            }
            InsertResult::IpLimited => {
                self.replace(node, true);
            }
        }
    }

    /// Mark as failure for the specified node.
    pub fn note_failure(
        &mut self, id: &NodeId, by_connection: bool, trusted_only: bool,
    ) {
        self.trusted_nodes.note_failure(id, by_connection);

        if !trusted_only {
            self.untrusted_nodes.note_failure(id, by_connection);
        }
    }

    /// Mark as success for the specified node.
    pub fn note_success(
        &mut self, id: &NodeId, token: Option<StreamToken>, trusted_only: bool,
    ) {
        self.trusted_nodes.note_success(id, token.is_some(), token);

        if !trusted_only {
            self.untrusted_nodes
                .note_success(id, token.is_some(), token);
        }
    }

    /// Get node from trusted and/or untrusted node table for the specified id.
    pub fn get(&self, id: &NodeId, trusted_only: bool) -> Option<&Node> {
        self.trusted_nodes.get(id).or_else(|| {
            if trusted_only {
                None
            } else {
                self.untrusted_nodes.get(id)
            }
        })
    }

    pub fn sample_trusted_nodes(
        &self, count: u32, filter: &IpFilter,
    ) -> Vec<NodeEntry> {
        self.trusted_nodes.sample_nodes(count, filter)
    }

    pub fn sample_trusted_node_ids(
        &self, count: u32, filter: &IpFilter,
    ) -> Vec<NodeId> {
        self.trusted_nodes.sample_node_ids(count, filter)
    }

    /// Persist trust and untrusted node tables and clear all useless nodes.
    pub fn save(&mut self) {
        self.trusted_nodes.save();
        self.trusted_nodes.clear_useless();

        self.untrusted_nodes.save();
        self.untrusted_nodes.clear_useless();
    }

    /// Promote untrusted nodes to trusted with the given duration.
    pub fn promote(&mut self, node_ids: Vec<NodeId>, due: Duration) {
        for id in node_ids.iter() {
            if self.trusted_nodes.contains(id) {
                continue;
            }

            if let Some(node) = self.untrusted_nodes.get(id) {
                if let Some(lc) = node.last_connected {
                    if lc.success_for_duration(due) {
                        if let Some(removed_node) =
                            self.untrusted_nodes.remove_with_id(id)
                        {
                            // IP address not changed and always allow to add.
                            self.trusted_nodes.add_node(removed_node, false);
                        }
                    }
                }
            }
        }
    }

    pub fn demote(&mut self, node_id: &NodeId) {
        if let Some(removed_trusted_node) =
            self.trusted_nodes.remove_with_id(node_id)
        {
            self.untrusted_nodes.add_node(removed_trusted_node, false);
        }
    }

    /// Remove node from database for the specified id
    pub fn remove(&mut self, id: &NodeId) -> Option<Node> {
        let node = self
            .trusted_nodes
            .remove_with_id(id)
            .or_else(|| self.untrusted_nodes.remove_with_id(id));

        match node {
            None => None,
            Some(n) => {
                assert!(self.ip_limit.on_delete(&n.endpoint.address.ip(), id));
                Some(n)
            }
        }
    }

    fn init(ip_limit: &mut NodeIpLimit, table: &NodeTable) {
        if !ip_limit.is_enabled() {
            return;
        }

        table.visit(|id| {
            let node = table.get(id).expect("Node should exist during visit");
            let ip = node.endpoint.address.ip();

            if !ip_limit.on_add(ip, node.id) {
                warn!("node not added into database, ip = {:?}, id = {:?}, quota = {}", ip, node.id, ip_limit.get_quota());
            }

            true
        });
    }

    fn pre_insert_untrusted(&mut self, node: &Node) -> InsertResult {
        let new_ip = node.endpoint.address.ip();

        match self.untrusted_nodes.get(&node.id) {
            Some(old_node) => {
                let old_ip = old_node.endpoint.address.ip();
                if new_ip == old_ip {
                    return InsertResult::Updated;
                }

                if !self.ip_limit.on_add(new_ip, node.id.clone()) {
                    return InsertResult::IpLimited;
                }

                assert!(self.ip_limit.on_delete(&old_ip, &node.id));
                InsertResult::IpUpdated
            }
            None => {
                if self.ip_limit.on_add(new_ip, node.id.clone()) {
                    InsertResult::Added
                } else {
                    InsertResult::IpLimited
                }
            }
        }
    }

    fn replace(&mut self, new_node: Node, as_trusted: bool) -> Option<Node> {
        let ip = new_node.endpoint.address.ip();
        let node_ids = self.ip_limit.get_keys(&ip)?;

        // priority definitions:
        //   - untrusted (0) < trusted (10)
        //   - last_contact: unknown (0) < failure (1) < success (2)
        //   - contact time
        let get_priority = |trusted: bool, node: &Node| {
            let priority = if trusted { 10 } else { 0 };
            match node.last_contact {
                None => (priority, SystemTime::UNIX_EPOCH),
                Some(contact) => match contact {
                    NodeContact::Failure(t) => (priority + 1, t),
                    NodeContact::Success(t) => (priority + 2, t),
                },
            }
        };

        let mut min_priority = (100, SystemTime::UNIX_EPOCH);
        let mut min_node = None;

        for id in node_ids {
            let mut cur_node = None;
            let cur_priority = if let Some(node) = self.untrusted_nodes.get(id)
            {
                cur_node = Some(node);
                get_priority(false, node)
            } else if let Some(node) = self.trusted_nodes.get(id) {
                cur_node = Some(node);
                get_priority(true, node)
            } else {
                (0, SystemTime::UNIX_EPOCH)
            };

            if cur_priority.0 > min_priority.0 {
                continue;
            }

            if cur_priority.0 < min_priority.0
                || cur_priority.1 < min_priority.1
            {
                min_priority = cur_priority;
                min_node = cur_node;
            }
        }

        let replaced_node_id = min_node?.id.clone();
        let replaced_node = self.remove(&replaced_node_id)?;

        assert!(self.ip_limit.on_add(ip, new_node.id.clone()));
        if let Some(old_node) = self.untrusted_nodes.get(&new_node.id) {
            let old_ip = old_node.endpoint.address.ip();
            assert!(self.ip_limit.on_delete(&old_ip, &old_node.id));
        }
        if as_trusted {
            self.trusted_nodes.add_node(new_node, false);
        } else {
            self.untrusted_nodes.add_node(new_node, false);
        }

        Some(replaced_node)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InsertResult {
    Added,     // add a new node
    Updated,   // update a node without IP address changed
    IpUpdated, // update a node with IP address changed
    IpLimited, // maximum nodes reached per IP address
}

#[cfg(test)]
mod tests {
    use super::{InsertResult, NodeDatabase};
    use crate::{
        ip_limit::NodeIpLimit,
        node_table::{Node, NodeEndpoint, NodeEntry, NodeId, NodeTable},
    };
    use std::{net::IpAddr, str::FromStr};

    fn new_node(addr: &str) -> Node {
        Node::new(NodeId::random(), NodeEndpoint::from_str(addr).unwrap())
    }

    fn new_ip(ip: &str) -> IpAddr { IpAddr::from_str(ip).unwrap() }

    fn new_entry(addr: &str) -> NodeEntry {
        NodeEntry {
            id: NodeId::random(),
            endpoint: NodeEndpoint::from_str(addr).unwrap(),
        }
    }

    #[test]
    fn test_insert_with_token_trusted_updated() {
        let mut db = NodeDatabase::new(None, 1);

        // add trusted node, whose token is None
        let entry = new_entry("127.0.0.1:999");
        db.insert_trusted(entry.clone());
        assert_eq!(db.get(&entry.id, true).unwrap().stream_token, None);

        // update node with token 3
        db.insert_with_token(entry.clone(), 3);
        assert_eq!(db.get(&entry.id, true).unwrap().stream_token, Some(3));
    }

    #[test]
    fn test_insert_with_token_untrusted_added() {
        let mut db = NodeDatabase::new(None, 1);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(5));
    }

    #[test]
    fn test_insert_with_token_untrusted_updated() {
        let mut db = NodeDatabase::new(None, 1);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // update node with new token
        db.insert_with_token(entry.clone(), 8);
        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_untrusted_ip_updated() {
        let mut db = NodeDatabase::new(None, 1);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // update node with new ip and token
        let entry = new_entry("127.0.0.2:999");
        db.insert_with_token(entry.clone(), 8);
        assert_eq!(db.get(&entry.id, true), None);
        let node = db.get(&entry.id, false).unwrap();
        assert_eq!(node.endpoint, entry.endpoint);
        assert_eq!(node.stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_untrusted_replace_added() {
        let mut db = NodeDatabase::new(None, 1);

        // add a node
        let entry = new_entry("127.0.0.1:999");
        let ip = new_ip("127.0.0.1");
        let node_id = entry.id.clone();
        db.insert_with_token(entry.clone(), 5);
        assert_eq!(db.ip_limit.get_keys(&ip).unwrap().len(), 1);

        // add new node with old IP address, previous node will be replaced.
        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 9);
        assert_eq!(db.get(&node_id, false), None); // old node was repalced
        let node = db.get(&entry.id, false).unwrap();
        assert_eq!(node.endpoint, entry.endpoint);
        assert_eq!(node.stream_token, Some(9));
        assert_eq!(db.ip_limit.get_keys(&ip).unwrap().len(), 1);
    }

    #[test]
    fn test_insert_with_token_untrusted_replace_updated() {
        let mut db = NodeDatabase::new(None, 1);

        // add node1
        let entry1 = new_entry("127.0.0.1:999");
        let ip1 = new_ip("127.0.0.1");
        db.insert_with_token(entry1.clone(), 3);
        assert_eq!(db.ip_limit.get_keys(&ip1).unwrap().len(), 1);

        // add node2
        let entry2 = new_entry("127.0.0.2:999");
        let ip2 = new_ip("127.0.0.2");
        db.insert_with_token(entry2.clone(), 4);
        assert_eq!(db.ip_limit.get_keys(&ip2).unwrap().len(), 1);

        // update node2's IP address to 127.0.0.1, node1 will be removed
        let mut entry = new_entry("127.0.0.1:999");
        entry.id = entry2.id.clone();
        db.insert_with_token(entry.clone(), 5);

        // node1 removed
        assert_eq!(db.get(&entry1.id, false), None);

        // node2 updated
        let node = db.get(&entry.id, false).unwrap();
        assert_eq!(node.endpoint, entry.endpoint);
        assert_eq!(node.stream_token, Some(5));

        // check ip_limits
        assert_eq!(db.ip_limit.get_keys(&ip1).unwrap().len(), 1);
        assert_eq!(db.ip_limit.get_keys(&ip2), None);
    }

    #[test]
    fn test_insert_with_promotion() {
        let mut db = NodeDatabase::new(None, 1);

        // add untrusted node
        let entry = new_entry("127.0.0.1:999");
        db.insert(entry.clone());
        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).is_some(), true);

        // update node and promote
        db.insert_with_promotion(entry.clone());
        assert_eq!(db.get(&entry.id, true).is_some(), true);
    }

    #[test]
    fn test_demote() {
        let mut db = NodeDatabase::new(None, 1);

        // add a trusted node
        let entry = new_entry("127.0.0.1:999");
        db.insert_trusted(entry.clone());
        assert_eq!(db.get(&entry.id, true).is_some(), true);

        // demote the trusted node to untrusted
        db.demote(&entry.id);
        assert_eq!(db.get(&entry.id, true), None);
        assert!(db.get(&entry.id, false).is_some());
    }

    #[test]
    fn test_remove() {
        let mut db = NodeDatabase::new(None, 1);

        // add trusted node
        let entry1 = new_entry("127.0.0.1:999");
        db.insert_trusted(entry1.clone());
        assert_eq!(db.get(&entry1.id, true).is_some(), true);

        // add untrusted node
        let entry2 = new_entry("127.0.0.2:999");
        db.insert_with_token(entry2.clone(), 9);
        assert_eq!(db.get(&entry2.id, false).is_some(), true);

        // delete nodes
        assert_eq!(db.remove(&NodeId::random()), None);
        assert_eq!(db.remove(&entry1.id).unwrap().endpoint, entry1.endpoint);
        assert_eq!(db.remove(&entry2.id).unwrap().endpoint, entry2.endpoint);

        assert_eq!(db.get(&entry1.id, true), None);
        assert_eq!(db.get(&entry2.id, false), None);
    }

    #[test]
    fn test_init() {
        let mut table = NodeTable::new(None, true);
        table.add_node(new_node("127.0.0.1:777"), false);
        table.add_node(new_node("127.0.0.1:888"), false);
        table.add_node(new_node("192.168.0.100:777"), false);

        // not enabled
        let mut limit = NodeIpLimit::new(0);
        NodeDatabase::init(&mut limit, &table);
        assert_eq!(limit.get_keys(&new_ip("127.0.0.1")), None);
        assert_eq!(limit.get_keys(&new_ip("192.168.0.100")), None);

        // enabled with enough quota
        let mut limit = NodeIpLimit::new(2);
        NodeDatabase::init(&mut limit, &table);
        assert_eq!(limit.get_keys(&new_ip("127.0.0.1")).unwrap().len(), 2);
        assert_eq!(limit.get_keys(&new_ip("192.168.0.100")).unwrap().len(), 1);

        // enabled with less quota
        let mut limit = NodeIpLimit::new(1);
        NodeDatabase::init(&mut limit, &table);
        assert_eq!(limit.get_keys(&new_ip("127.0.0.1")).unwrap().len(), 1);
    }

    #[test]
    fn test_pre_insert_untrusted() {
        let mut db = NodeDatabase::new(None, 1);

        let entry1 = new_entry("127.0.0.1:999");
        let ip1 = new_ip("127.0.0.1");
        let id1 = entry1.id.clone();
        db.insert(entry1);

        let ip2 = new_ip("127.0.0.2");
        db.insert(new_entry("127.0.0.2:999"));

        // new added with different IP
        let node = new_node("127.0.0.3:999");
        let ip3 = new_ip("127.0.0.3");
        assert_eq!(db.pre_insert_untrusted(&node), InsertResult::Added);
        assert_eq!(db.ip_limit.get_keys(&ip3).unwrap().len(), 1); // new ip added

        // new added with same IP
        let node = new_node("127.0.0.1:999");
        assert_eq!(db.pre_insert_untrusted(&node), InsertResult::IpLimited);
        assert_eq!(db.ip_limit.get_keys(&ip1).unwrap().len(), 1); // not added

        // updated with same IP
        let mut node = new_node("127.0.0.1:999");
        node.id = id1.clone();
        assert_eq!(db.pre_insert_untrusted(&node), InsertResult::Updated);
        assert_eq!(db.ip_limit.get_keys(&ip1).unwrap().len(), 1); // nothing changed

        // updated with existing IP
        let mut node = new_node("127.0.0.2:999");
        node.id = id1.clone();
        assert_eq!(db.pre_insert_untrusted(&node), InsertResult::IpLimited);
        assert_eq!(db.ip_limit.get_keys(&ip1).unwrap().len(), 1); // IP1 not changed
        assert_eq!(db.ip_limit.get_keys(&ip2).unwrap().len(), 1); // IP2 not changed

        // updated with different IP
        let mut node = new_node("127.0.0.4:999");
        node.id = id1.clone();
        let ip4 = new_ip("127.0.0.4");
        assert_eq!(db.pre_insert_untrusted(&node), InsertResult::IpUpdated);
        assert_eq!(db.ip_limit.get_keys(&ip1), None); // IP1 removed
        assert_eq!(db.ip_limit.get_keys(&ip4).unwrap().len(), 1); // IP4 added
    }
}
