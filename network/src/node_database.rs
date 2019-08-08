// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip::{NodeIpLimit, NodeTagIndex, ValidateInsertResult},
    node_table::{Node, NodeContact, NodeEntry, NodeId, NodeTable},
    IpFilter,
};
use io::StreamToken;
use std::{collections::HashSet, net::IpAddr, time::Duration};

/// Node database maintains all P2P nodes in trusted and untrusted node tables,
/// and supports to limit the number of nodes for the same IP address.
///
/// # Insert a node
///
/// There are 3 scenarios to insert a node into database:
/// 1. Receive the "hello" handshaking message from ingress TCP connection,
/// and add the node with `StreamToken` as untrusted if not exists in database.
/// Otherwise, overwrite the existing node in trusted or untrusted table,
/// including endpoint, last contact and connection information.
/// 2. Receive the "pong" message from UDP discovery, and add the node as
/// trusted if not exists, or promote it to trusted if it is untrusted.
/// Otherwise, just update the last contact information in trusted table.
/// 3. RPC explicitly add a trusted node. If the node is an existing
/// untrusted one, promote it to trusted.
///
/// # Update node information
///
/// ## note_success
/// When actively connect to a sampled trusted node, updates the node last
/// contact time. On the other hand, when received "ping" message from "UDP"
/// message, update the node last contact time.
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
/// # Subnet limitation
///
/// Attacker could easily simulate a large amount of malicious nodes of
/// different node IDs with same IP address or IPs from same subnet. To
/// avoid such kind of attack, user could limits the number of nodes for
/// one IP address and subnet. By default, only 1 node allowed for a
/// single IP address and 32 nodes for a subnet C (ip/24), and will evict
/// an existing old node in following 2 scenarios:
///
/// ## Scenario 1: add or update node with existing IP address
/// For example, "node_1" with "IP_1" already in database, and to add a new node
/// "node_2" with the same address "IP_1". "node_1" will be evicted, and then
/// add "node_2" with "IP_1".
///
/// ## Scenario 2: add or update node with new IP address
/// If the subnet quota of the IP address is not enough, some node in the
/// same subnet may be evicted. If evict one, then add or update the node
/// with new IP address. Otherwise, do not add or update the node.
///
/// ## Eviction rule
/// If the subnet quota is not enough, the rule to select evictee is as
/// following: 1. Select untrusted node prior to trusted node.
/// 2. Select node that has been contacted long time ago.
/// 3. Randomly select one without "fresher" bias.
pub struct NodeDatabase {
    trusted_nodes: NodeTable,
    untrusted_nodes: NodeTable,
    ip_limit: NodeIpLimit,

    // Only used for sampling trusted nodes with desired tag.
    // It is updated in following cases:
    // 1. add tag indices when initialize the trusted node table
    // 2. add tag indices when promote a node
    // 3. remove tag indices when demote a node
    // 4. remove tag indices when delete a trusted node
    trusted_node_tag_index: NodeTagIndex,
}

impl NodeDatabase {
    pub fn new(path: Option<String>, subnet_quota: usize) -> Self {
        let trusted_nodes = NodeTable::new(path.clone(), true);
        let untrusted_nodes = NodeTable::new(path.clone(), false);
        let ip_limit = NodeIpLimit::new(subnet_quota);
        let trusted_node_tag_index =
            NodeTagIndex::new_with_node_table(&trusted_nodes);

        let mut db = NodeDatabase {
            trusted_nodes,
            untrusted_nodes,
            ip_limit,
            trusted_node_tag_index,
        };

        db.init(false);
        db.init(true);

        db
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

        if self.trusted_nodes.contains(&node.id) {
            if self.insert_ip_limit(node.id.clone(), ip, true) {
                self.trusted_nodes.add_node(node, false);
            }
        } else if self.insert_ip_limit(node.id.clone(), ip, false) {
            self.untrusted_nodes.add_node(node, false);
        }
    }

    fn insert_ip_limit(
        &mut self, id: NodeId, ip: IpAddr, trusted: bool,
    ) -> bool {
        let mut evictee = None;

        match self.ip_limit.validate_insertion(&id, &ip, self) {
            ValidateInsertResult::AlreadyExists => return true,
            ValidateInsertResult::QuotaNotEnough => return false,
            ValidateInsertResult::QuotaEnough => {}
            ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
            ValidateInsertResult::Evict(id) => evictee = Some(id),
        }

        if let Some(id) = &evictee {
            self.remove(id);
        }

        self.ip_limit.insert(id, ip, trusted, evictee)
    }

    /// Add a new trusted node if not exists. Otherwise, update the existing
    /// node with the specified `entry`, and promote the node to trusted if it
    /// is untrusted.
    pub fn insert_with_promotion(&mut self, entry: NodeEntry) {
        let mut node = Node::new(entry.id, entry.endpoint);
        node.last_contact = Some(NodeContact::success());

        let ip = node.endpoint.address.ip();

        if self.untrusted_nodes.contains(&node.id) {
            if let Some(old_node) = self.promote_with_untrusted(&node.id, ip) {
                node.last_connected = old_node.last_connected;
                node.stream_token = old_node.stream_token;
                self.trusted_node_tag_index.add_node(&node);
                self.trusted_nodes.add_node(node, false);
            }
        } else if self.insert_ip_limit(node.id.clone(), ip, true) {
            self.trusted_nodes.update_last_contact(node);
        }
    }

    fn promote_with_untrusted(
        &mut self, id: &NodeId, new_ip: IpAddr,
    ) -> Option<Node> {
        let mut evictee = None;

        match self.ip_limit.validate_insertion(id, &new_ip, self) {
            ValidateInsertResult::AlreadyExists => {}
            ValidateInsertResult::QuotaNotEnough => return None,
            ValidateInsertResult::QuotaEnough => {}
            ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
            ValidateInsertResult::Evict(id) => evictee = Some(id),
        }

        if let Some(id) = &evictee {
            self.remove(id);
        }

        self.ip_limit.remove(id);
        self.ip_limit.insert(id.clone(), new_ip, true, evictee);

        self.untrusted_nodes.remove_with_id(id)
    }

    /// Add a new trusted node if not exists, or promote the existing untrusted
    /// node.
    pub fn insert_trusted(&mut self, entry: NodeEntry) {
        if self.trusted_nodes.contains(&entry.id) {
            return;
        }

        let mut node = Node::new(entry.id.clone(), entry.endpoint.clone());
        let ip = node.endpoint.address.ip();

        if self.untrusted_nodes.contains(&node.id) {
            if let Some(old_node) = self.promote_with_untrusted(&node.id, ip) {
                node.last_contact = old_node.last_contact;
                node.last_connected = old_node.last_connected;
                node.stream_token = old_node.stream_token;
                self.trusted_node_tag_index.add_node(&node);
                self.trusted_nodes.add_node(node, false);
            }
        } else if self.insert_ip_limit(node.id.clone(), ip, true) {
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
        if !self.ip_limit.is_enabled() {
            return self.trusted_nodes.sample_nodes(count, filter);
        }

        let mut entries = Vec::new();

        for id in self.ip_limit.sample_trusted(count) {
            if let Some(node) = self.get(&id, true) {
                entries.push(NodeEntry {
                    id,
                    endpoint: node.endpoint.clone(),
                });
            }
        }

        entries
    }

    pub fn sample_trusted_node_ids(
        &self, count: u32, filter: &IpFilter,
    ) -> HashSet<NodeId> {
        if self.ip_limit.is_enabled() {
            self.ip_limit.sample_trusted(count)
        } else {
            self.trusted_nodes.sample_node_ids(count, filter)
        }
    }

    // todo call this method to sample Archive nodes for outgoing connection
    #[allow(dead_code)]
    pub fn sample_trusted_node_ids_with_tag(
        &self, count: u32, key: &String, value: &String,
    ) -> HashSet<NodeId> {
        // todo always enable ip_limit and remove the legacy sampling methods in
        // node table
        self.trusted_node_tag_index
            .sample(count, key, value)
            .unwrap_or_else(|| HashSet::new())
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
                            self.trusted_node_tag_index.add_node(&removed_node);
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
            self.trusted_node_tag_index
                .remove_node(&removed_trusted_node);
            self.untrusted_nodes.add_node(removed_trusted_node, false);
        }
    }

    /// Remove node from database for the specified id
    pub fn remove(&mut self, id: &NodeId) -> Option<Node> {
        let node = if let Some(node) = self.trusted_nodes.remove_with_id(id) {
            self.trusted_node_tag_index.remove_node(&node);
            node
        } else if let Some(node) = self.untrusted_nodes.remove_with_id(id) {
            node
        } else {
            return None;
        };

        self.ip_limit.remove(id);

        Some(node)
    }

    fn init(&mut self, trusted: bool) {
        let nodes = if trusted {
            self.trusted_nodes.all()
        } else {
            self.untrusted_nodes.all()
        };

        for id in nodes {
            let ip = if trusted {
                self.trusted_nodes
                    .get(&id)
                    .expect("node not found in trusted table")
                    .endpoint
                    .address
                    .ip()
            } else {
                self.untrusted_nodes
                    .get(&id)
                    .expect("node not found in untrusted table")
                    .endpoint
                    .address
                    .ip()
            };

            let mut allowed = true;
            let mut evictee = None;

            match self.ip_limit.validate_insertion(&id, &ip, self) {
                ValidateInsertResult::AlreadyExists => {
                    panic!("node id is not unique in database")
                }
                ValidateInsertResult::QuotaNotEnough => allowed = false,
                ValidateInsertResult::QuotaEnough => {}
                ValidateInsertResult::OccupyIp(id) => evictee = Some(id),
                ValidateInsertResult::Evict(id) => evictee = Some(id),
            }

            if allowed {
                if let Some(evictee_id) = &evictee {
                    if trusted {
                        self.trusted_nodes.remove_with_id(&evictee_id);
                    } else {
                        self.untrusted_nodes.remove_with_id(&evictee_id);
                    }
                }

                assert!(self.ip_limit.insert(id, ip, trusted, evictee));
            } else {
                if trusted {
                    self.trusted_nodes.remove_with_id(&id);
                } else {
                    self.untrusted_nodes.remove_with_id(&id);
                }
            }
        }
    }

    pub fn set_tag(&mut self, id: NodeId, key: &str, value: &str) {
        let (trusted, node) =
            if let Some(node) = self.trusted_nodes.get_mut(&id) {
                (true, node)
            } else if let Some(node) = self.untrusted_nodes.get_mut(&id) {
                (false, node)
            } else {
                return;
            };

        // add or update tag for node
        let removed = node.tags.insert(key.into(), value.into());

        // do not update tag index for untrusted node
        if !trusted {
            return;
        }

        let subnet = self
            .ip_limit
            .subnet(&id)
            .expect("node index should always exist");

        // remove the old tag index
        if let Some(removed) = removed {
            self.trusted_node_tag_index.remove(
                &id,
                subnet,
                &key.into(),
                &removed,
            );
        }

        // add new tag index
        self.trusted_node_tag_index.insert(
            id,
            subnet,
            key.into(),
            value.into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::NodeDatabase;
    use crate::node_table::{NodeEndpoint, NodeEntry, NodeId};
    use std::str::FromStr;

    fn new_entry(addr: &str) -> NodeEntry {
        NodeEntry {
            id: NodeId::random(),
            endpoint: NodeEndpoint::from_str(addr).unwrap(),
        }
    }

    #[test]
    fn test_insert_with_token_added() {
        let mut db = NodeDatabase::new(None, 2);

        // add a new node
        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // should be untrusted with stream token 5
        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(5));
    }

    #[test]
    fn test_insert_with_token_updated_trusted() {
        let mut db = NodeDatabase::new(None, 2);

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
        let mut db = NodeDatabase::new(None, 2);

        let entry = new_entry("127.0.0.1:999");
        db.insert_with_token(entry.clone(), 5);

        // update node with new token
        db.insert_with_token(entry.clone(), 8);
        assert_eq!(db.get(&entry.id, true), None);
        assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(8));
    }

    #[test]
    fn test_insert_with_token_updated_new_ip() {
        let mut db = NodeDatabase::new(None, 2);

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
        let mut db = NodeDatabase::new(None, 2);

        // add node1
        let entry1 = new_entry("127.0.0.1:999");
        db.insert_with_token(entry1.clone(), 3);

        // add node2
        let entry2 = new_entry("127.0.0.2:999");
        db.insert_with_token(entry2.clone(), 4);

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
    }

    #[test]
    fn test_demote() {
        let mut db = NodeDatabase::new(None, 2);

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
        let mut db = NodeDatabase::new(None, 2);

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
}
