// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip_limit::NodeIpLimit,
    node_table::{Node, NodeContact, NodeEntry, NodeId, NodeTable},
    IpFilter,
};
use io::StreamToken;
use std::{
    cmp::Ordering,
    net::IpAddr,
    time::{Duration, SystemTime},
};

/// Node database maintains all P2P nodes in trusted and untrusted node tables,
/// and supports to limit the number of nodes for the same IP address.
///
/// # Insert a node
///
/// There are 4 scenarios to insert a node into database:
/// 1. Receive the "hello" handshaking message from ingress TCP connection,
/// and add the node with `StreamToken` as untrusted if not exists in database.
/// Otherwise, overwrite the existing node in trusted or untrusted table,
/// including endpoint, last contact and connection information.
/// 2. Receive a "ping" message from UDP discovery, and add the node as
/// untrusted if not exists in database. Otherwise, overwrite the existing
/// node in trusted or untrusted table.
/// 3. Receive the "pong" message from UDP discovery, and add the node as
/// untrusted if not exists in database. Otherwise, overwrite the existing
/// node in trusted or untrusted table.
/// 4. RPC explicitly add a trusted node. If the node is an existing
/// untrusted one, promote it to trusted.
///
/// # Update node information
///
/// ## note_success
/// When actively connect to a sampled trusted node, updates the node last
/// contact time.
///
/// ## note_failure
/// Mark the node's last contact to failure for any error, e.g.
/// - UDP request timeout.
/// - Failed to create TCP connection/session.
/// - Failed to communicate due to invalid protocol message.
///
/// # Promote/Demote
///
/// ## Promote
/// Periodically promote untrusted nodes from ingress TCP connection with
/// configured timespan.
///
/// ## Demote
/// Demote a node to untrusted when failed to handle protocol messages.
///
/// # IP limitation
///
/// Attacker could easily simulate a large amount of malicious nodes of
/// different node IDs and same IP address. To avoid such kind of attack, user
/// could limits the number of nodes for one IP address. By default, only 1 node
/// allowed for a IP address, and has to replace an existing old node in
/// following 2 scenarios.
///
/// ## Scenario 1: add new node with existing IP address
/// For example, "node_1" with "IP_1" already in database, and to add a new node
/// "node_2" with the same address "IP_1". Due to default IP limitation (1 node
/// per IP), "node_1" will be removed, and then add "node_2" with "IP_1".
///
/// ## Scenario 2: update node with existing IP address
/// For example, "node_1" with "IP_1" and "node_2" with "IP_2" already in
/// database, and to update "node_2" with existing address "IP_1". Due to
/// default IP limitation (1 node per IP), "node_1" will be removed, and then
/// update "node_2" with "IP_1". Besides, "IP_2" never exists in database
/// anymore.
///
/// ## Remove node with priority
/// If multiple nodes allowed for 1 IP address, the node with minimum priority
/// will be removed in above 2 scenarios. The priority is defined as below:
/// 1. untrusted node < trusted node
/// 2. Node last contact status: unknown < failure < success
/// 3. Node last contact time: the earlier the smaller
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

    /// Add a new untrusted node if not exists. Otherwise, update the existing
    /// node with specified `entry` and `stream_token`.
    pub fn insert_with_token(
        &mut self, entry: NodeEntry, stream_token: StreamToken,
    ) {
        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());
        node.last_connected = Some(NodeContact::success());
        node.stream_token = Some(stream_token);

        let ip = node.endpoint.address.ip();

        if let Some(old_node) = self.trusted_nodes.get(&node.id) {
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.trusted_nodes.add_node(node, false);
        } else if let Some(old_node) = self.untrusted_nodes.get(&node.id) {
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.untrusted_nodes.add_node(node, false);
        } else {
            self.force_new_ip_limit(&node.id, ip);
            self.untrusted_nodes.add_node(node, false);
        }
    }

    /// Add a new untrusted node if not exists. Otherwise, update the existing
    /// node with the specified `entry`. If node exists, it will update its
    /// last contact information.
    pub fn insert(&mut self, entry: NodeEntry) {
        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        let ip = node.endpoint.address.ip();

        if let Some(old_node) = self.trusted_nodes.get(&node.id) {
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.trusted_nodes.update_last_contact(node);
        } else if let Some(old_node) = self.untrusted_nodes.get(&node.id) {
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.untrusted_nodes.update_last_contact(node);
        } else {
            self.force_new_ip_limit(&node.id, ip);
            self.untrusted_nodes.add_node(node, false);
        }
    }

    /// Add a new trusted node if not exists. Otherwise, update the existing
    /// node with the specified `entry`, and promote the node to trusted if it
    /// is untrusted.
    pub fn insert_with_promotion(&mut self, entry: NodeEntry) {
        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        let ip = node.endpoint.address.ip();

        if let Some(old_node) = self.trusted_nodes.get(&node.id) {
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.trusted_nodes.update_last_contact(node);
        } else if let Some(old_node) =
            self.untrusted_nodes.remove_with_id(&node.id)
        {
            node.last_connected = old_node.last_connected;
            node.stream_token = old_node.stream_token;
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.trusted_nodes.add_node(node, false);
        } else {
            self.force_new_ip_limit(&node.id, ip);
            self.trusted_nodes.add_node(node, false);
        }
    }

    /// Add a new trusted node if not exists, or promote the existing untrusted
    /// node.
    pub fn insert_trusted(&mut self, entry: NodeEntry) {
        if self.trusted_nodes.contains(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id.clone(), entry.endpoint.clone());
        let ip = node.endpoint.address.ip();

        if let Some(old_node) = self.untrusted_nodes.remove_with_id(&node.id) {
            node.last_contact = old_node.last_contact;
            node.last_connected = old_node.last_connected;
            node.stream_token = old_node.stream_token;
            let old_ip = old_node.endpoint.address.ip();
            self.update_ip_limit(&node.id, old_ip, ip);
            self.trusted_nodes.add_node(node, false);
        } else {
            self.force_new_ip_limit(&node.id, ip);
            self.trusted_nodes.add_node(node, false);
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

    pub fn get_with_trusty(&self, id: &NodeId) -> Option<(bool, &Node)> {
        if let Some(node) = self.trusted_nodes.get(id) {
            Some((true, node))
        } else if let Some(node) = self.untrusted_nodes.get(id) {
            Some((false, node))
        } else {
            None
        }
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

    /// Demote the specified node to untrusted if it is trusted.
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

    /// Update the IP-NodeId mapping before update a node if its IP address
    /// changed.
    fn update_ip_limit(
        &mut self, node_id: &NodeId, old_ip: IpAddr, new_ip: IpAddr,
    ) {
        if old_ip != new_ip {
            self.force_new_ip_limit(node_id, new_ip);
            assert!(self.ip_limit.on_delete(&old_ip, node_id));
        }
    }

    /// Add a new IP-NodeId mapping. If IP limitation reached, remove the worst
    /// node of the same IP address.
    fn force_new_ip_limit(&mut self, node_id: &NodeId, ip: IpAddr) {
        if !self.ip_limit.on_add(ip, node_id.clone()) {
            assert_eq!(self.remove_worst_by_ip(ip).is_some(), true);
            assert_eq!(self.ip_limit.on_add(ip, node_id.clone()), true);
        }
    }

    /// Remove the worst node of specified IP address. The worst node has the
    /// minimum priority.
    fn remove_worst_by_ip(&mut self, ip: IpAddr) -> Option<Node> {
        let mut min_priority = NodePriority::MAX;
        let mut min_node = None;

        for id in self.ip_limit.get_keys(&ip)? {
            let mut cur_node = None;
            let cur_priority = if let Some(node) = self.untrusted_nodes.get(id)
            {
                cur_node = Some(node);
                NodePriority::new(false, node)
            } else if let Some(node) = self.trusted_nodes.get(id) {
                cur_node = Some(node);
                NodePriority::new(true, node)
            } else {
                NodePriority::MAX
            };

            if cur_priority < min_priority {
                min_priority = cur_priority;
                min_node = cur_node;
            }
        }

        let node_id = min_node?.id.clone();
        self.remove(&node_id)
    }
}

/// NodePriority defines the priority to remove when IP limitation reached. The
/// concrete definitions are as following:
/// - untrusted (0) < trusted (10)
/// - last_contact: unknown (0) < failure (1) < success (2)
/// - contact time
///
/// Node with minimum priority will be removed when IP limitation reached.
struct NodePriority {
    priority: usize,
    contact_time: SystemTime,
}

impl NodePriority {
    const MAX: NodePriority = NodePriority {
        priority: 100,
        contact_time: SystemTime::UNIX_EPOCH,
    };

    fn new(trusted: bool, node: &Node) -> Self {
        let mut priority = if trusted { 10 } else { 0 };
        let mut contact_time = SystemTime::UNIX_EPOCH;

        if let Some(contact) = node.last_contact {
            match contact {
                NodeContact::Failure(t) => {
                    priority += 1;
                    contact_time = t;
                }
                NodeContact::Success(t) => {
                    priority += 2;
                    contact_time = t;
                }
            }
        }

        NodePriority {
            priority,
            contact_time,
        }
    }
}

impl PartialOrd for NodePriority {
    fn partial_cmp(&self, other: &NodePriority) -> Option<Ordering> {
        Some(
            self.priority
                .cmp(&other.priority)
                .then_with(|| self.contact_time.cmp(&other.contact_time)),
        )
    }
}

impl PartialEq for NodePriority {
    fn eq(&self, other: &NodePriority) -> bool {
        self.priority == other.priority
            && self.contact_time == other.contact_time
    }
}

#[cfg(test)]
mod tests {
    use super::NodeDatabase;
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
    fn test_insert_with_token_added() {
        let mut db = NodeDatabase::new(None, 1);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(5));
    }

    #[test]
    fn test_insert_with_token_added_ip_exists() {
        let mut db = NodeDatabase::new(None, 1);

        // add a node
        let entry1 = new_entry("127.0.0.1:999");
        let ip = new_ip("127.0.0.1");
        db.insert_with_token(entry1.clone(), 5);
        assert_eq!(db.ip_limit.get_keys(&ip).unwrap().len(), 1);

        // add new node with old IP address, previous node will be replaced.
        let entry2 = new_entry("127.0.0.1:999");
        db.insert_with_token(entry2.clone(), 9);
        assert_eq!(db.get(&entry1.id, false), None); // old node was repalced
        let node = db.get(&entry2.id, false).unwrap();
        assert_eq!(node.endpoint, entry2.endpoint);
        assert_eq!(node.stream_token, Some(9));
        assert_eq!(db.ip_limit.get_keys(&ip).unwrap().len(), 1);
    }

    #[test]
    fn test_insert_with_token_updated_trusted() {
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
    fn test_insert_with_token_updated_untrusted() {
        let mut db = NodeDatabase::new(None, 1);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // update node with new token
        db.insert_with_token(entry.clone(), 8);
        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_updated_new_ip() {
        let mut db = NodeDatabase::new(None, 1);

        let entry1 = new_entry("127.0.0.1:999");
        db.insert_with_token(entry1.clone(), 5);

        // update node with new ip and token
        let mut entry2 = new_entry("127.0.0.2:999");
        entry2.id = entry1.id;
        db.insert_with_token(entry2.clone(), 8);
        let node = db.get(&entry1.id, false).unwrap();
        assert_eq!(node.endpoint, entry2.endpoint);
        assert_eq!(node.stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_updated_ip_exists() {
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

        // update node2's IP address to ip1, node1 will be removed
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
}
