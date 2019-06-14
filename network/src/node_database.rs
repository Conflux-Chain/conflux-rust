// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    node_table::{Node, NodeContact, NodeEntry, NodeId, NodeTable},
    IpFilter,
};
use io::StreamToken;
use std::{collections::HashMap, net::IpAddr, time::Duration};

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

        ip_limit.init(&trusted_nodes);
        ip_limit.init(&untrusted_nodes);

        NodeDatabase {
            trusted_nodes,
            untrusted_nodes,
            ip_limit,
        }
    }

    /// add or update a node with the specified `entry` and `stream_token`.
    pub fn insert_with_token(
        &mut self, entry: NodeEntry, stream_token: StreamToken,
    ) -> InsertResult {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(
                &entry.id,
                true,
                Some(stream_token),
            );
            return InsertResult::Updated;
        }

        match self
            .ip_limit
            .validate_insertion(&self.untrusted_nodes, &entry)
        {
            result @ InsertResult::Added | result @ InsertResult::Updated => {
                let mut node = Node::new(entry.id, entry.endpoint);
                node.last_contact = Some(NodeContact::success());
                node.last_connected = Some(NodeContact::success());
                node.stream_token = Some(stream_token);

                // overwrite endpoint of untrusted node.
                self.untrusted_nodes.add_node(node, false);

                result
            }
            result @ _ => result,
        }
    }

    /// Add or update a node with the specified `entry`.
    pub fn insert(&mut self, entry: NodeEntry) -> InsertResult {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(&entry.id, false, None);
            return InsertResult::Updated;
        }

        match self
            .ip_limit
            .validate_insertion(&self.untrusted_nodes, &entry)
        {
            result @ InsertResult::Added | result @ InsertResult::Updated => {
                let mut node = Node::new(entry.id, entry.endpoint);
                node.last_contact = Some(NodeContact::success());
                self.untrusted_nodes.update_last_contact(node);
                result
            }
            result @ _ => result,
        }
    }

    /// Add or update a node with the specified `entry`, and promote the node to
    /// trusted if it is untrusted.
    pub fn insert_with_promotion(&mut self, entry: NodeEntry) -> InsertResult {
        if self.trusted_nodes.contains(&entry.id) {
            self.trusted_nodes.note_success(&entry.id, false, None);
            return InsertResult::Updated;
        }

        match self
            .ip_limit
            .validate_insertion(&self.untrusted_nodes, &entry)
        {
            result @ InsertResult::Added | result @ InsertResult::Updated => {
                let mut node = Node::new(entry.id, entry.endpoint);
                node.last_contact = Some(NodeContact::success());

                if let Some(old_node) =
                    self.untrusted_nodes.remove_with_id(&entry.id)
                {
                    node.last_connected = old_node.last_connected;
                    node.stream_token = old_node.stream_token;
                }

                self.trusted_nodes.add_node(node, false);

                result
            }
            result @ _ => result,
        }
    }

    /// Add a new trusted node if not exists, or promote an existing untrusted
    /// node.
    pub fn insert_trusted(&mut self, entry: NodeEntry) -> Option<InsertResult> {
        if self.trusted_nodes.contains(&entry.id) {
            return None;
        }

        let mut node = Node::new(entry.id.clone(), entry.endpoint.clone());

        match self
            .ip_limit
            .validate_insertion(&self.untrusted_nodes, &entry)
        {
            InsertResult::Added => {
                self.trusted_nodes.add_node(node, false);
                Some(InsertResult::Added)
            }
            InsertResult::Updated => {
                if let Some(old_node) =
                    self.untrusted_nodes.remove_with_id(&entry.id)
                {
                    node.last_contact = old_node.last_contact;
                    node.last_connected = old_node.last_connected;
                    node.stream_token = old_node.stream_token;
                }

                self.trusted_nodes.add_node(node, false);
                Some(InsertResult::Updated)
            }
            result @ _ => Some(result),
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
                self.ip_limit.on_delete(n.endpoint.address.ip());
                Some(n)
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum InsertResult {
    Added,
    Updated,
    // the number of nodes reaches the maximum value for one IP address.
    IpLimited,
}

/// IP address limitation for P2P nodes.
pub struct NodeIpLimit {
    nodes_per_ip: usize, // 0 presents unlimited
    ip_to_nodes: HashMap<IpAddr, usize>,
}

impl NodeIpLimit {
    pub fn new(nodes_per_ip: usize) -> Self {
        debug!("NodeIpLimit::new: nodes_per_ip = {}", nodes_per_ip);
        NodeIpLimit {
            nodes_per_ip,
            ip_to_nodes: HashMap::new(),
        }
    }

    /// Initialize with give node table, and will not restrict the number
    /// of nodes per IP address.
    fn init(&mut self, table: &NodeTable) {
        if !self.is_enabled() {
            return;
        }

        table.visit(|id| {
            if let Some(node) = table.get(id) {
                let ip = node.endpoint.address.ip();
                let num = self.ip_to_nodes.entry(ip).or_insert(0);
                *num += 1;

                if *num > self.nodes_per_ip {
                    warn!("NodeIpLimit::init: too many nodes added, actual = {}, limited = {}", *num, self.nodes_per_ip);
                }
            } else {
                error!("NodeIpLimit::init: node not found when visit table");
            }

            true
        });
    }

    fn is_enabled(&self) -> bool { self.nodes_per_ip > 0 }

    /// Check if the specified IP address is allowed.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }

        match self.ip_to_nodes.get(ip) {
            Some(num) => *num < self.nodes_per_ip,
            None => true,
        }
    }

    /// Validate IP address when adding a new node.
    pub fn on_add(&mut self, ip: IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }

        let num_nodes = self.ip_to_nodes.entry(ip).or_insert(0);
        if *num_nodes < self.nodes_per_ip {
            *num_nodes += 1;
            true
        } else {
            false
        }
    }

    /// Validate IP address when updating an existing node.
    fn on_update(&mut self, old_ip: IpAddr, new_ip: IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }

        if old_ip == new_ip {
            return true;
        }

        if !self.on_add(new_ip) {
            return false;
        }

        self.on_delete(old_ip);

        true
    }

    /// Update the number of nodes for the specified IP address when deleting a
    /// node.
    pub fn on_delete(&mut self, ip: IpAddr) {
        if !self.is_enabled() {
            return;
        }

        if let Some(num) = self.ip_to_nodes.get_mut(&ip) {
            if *num <= 1 {
                self.ip_to_nodes.remove(&ip);
            } else {
                *num -= 1;
            }
        } else {
            error!("NodeIpLimit::on_delete: ip not found");
        }
    }

    fn validate_insertion(
        &mut self, table: &NodeTable, entry: &NodeEntry,
    ) -> InsertResult {
        let new_ip = entry.endpoint.address.ip();

        match table.get(&entry.id) {
            Some(old_node) => {
                let old_ip = old_node.endpoint.address.ip();

                if !self.on_update(old_ip, new_ip) {
                    InsertResult::IpLimited
                } else {
                    InsertResult::Updated
                }
            }
            None => {
                if !self.on_add(new_ip) {
                    InsertResult::IpLimited
                } else {
                    InsertResult::Added
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::node_table::{Node, NodeEndpoint, NodeEntry, NodeId};
    use std::{net::IpAddr, str::FromStr};

    fn new_node(addr: &str) -> Node {
        Node::new(NodeId::random(), NodeEndpoint::from_str(addr).unwrap())
    }

    fn new_ip(ip: &str) -> IpAddr { IpAddr::from_str(ip).unwrap() }

    fn new_entry(id: Option<NodeId>, addr: &str) -> NodeEntry {
        let id = id.or_else(|| Some(NodeId::random())).unwrap();
        let endpoint = NodeEndpoint::from_str(addr).unwrap();
        NodeEntry { id, endpoint }
    }

    #[cfg(test)]
    mod ip_limit_tests {
        use super::{
            super::{InsertResult, NodeIpLimit},
            new_entry, new_ip, new_node,
        };
        use crate::node_table::NodeTable;

        #[test]
        fn test_enabled() {
            assert_eq!(NodeIpLimit::new(0).is_enabled(), false);
            assert_eq!(NodeIpLimit::new(1).is_enabled(), true);
            assert_eq!(NodeIpLimit::new(4).is_enabled(), true);
        }

        #[test]
        fn test_init() {
            let mut table = NodeTable::new(None, true);
            table.add_node(new_node("127.0.0.1:777"), false);
            table.add_node(new_node("127.0.0.1:888"), false);
            table.add_node(new_node("192.168.0.100:777"), false);

            // not enabled
            let mut limit = NodeIpLimit::new(0);
            limit.init(&table);
            assert_eq!(limit.ip_to_nodes.len(), 0);

            // enabled
            let mut limit = NodeIpLimit::new(1);
            limit.init(&table);
            assert_eq!(limit.ip_to_nodes.len(), 2);
            assert_eq!(limit.ip_to_nodes[&new_ip("127.0.0.1")], 2);
            assert_eq!(limit.ip_to_nodes[&new_ip("192.168.0.100")], 1);
        }

        #[test]
        fn test_on_add() {
            let mut limit = NodeIpLimit::new(2);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), true);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), true);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), false);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), false);
        }

        #[test]
        fn test_on_update() {
            let mut limit = NodeIpLimit::new(1);
            let ip1 = new_ip("127.0.0.1");
            let ip2 = new_ip("127.0.0.2");
            assert_eq!(limit.on_add(ip1), true);
            assert_eq!(limit.on_add(ip2), true);

            // same ip allowed
            assert_eq!(limit.on_update(ip1, ip1), true);
            // exist ip not allowed
            assert_eq!(limit.on_update(ip1, ip2), false);

            // new ip allowed
            let ip3 = new_ip("127.0.0.3");
            assert_eq!(limit.on_update(ip1, ip3), true);
            assert_eq!(limit.ip_to_nodes.contains_key(&ip1), false);
            assert_eq!(limit.ip_to_nodes.contains_key(&ip3), true);
        }

        #[test]
        fn test_on_delete() {
            let mut limit = NodeIpLimit::new(2);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), true);
            assert_eq!(limit.on_add(new_ip("127.0.0.1")), true);
            assert_eq!(limit.ip_to_nodes[&new_ip("127.0.0.1")], 2);
            limit.on_delete(new_ip("127.0.0.1"));
            assert_eq!(limit.ip_to_nodes[&new_ip("127.0.0.1")], 1);
            limit.on_delete(new_ip("127.0.0.1"));
            assert_eq!(
                limit.ip_to_nodes.contains_key(&new_ip("127.0.0.1")),
                false
            );
        }

        #[test]
        fn test_validate_insertion() {
            let mut table = NodeTable::new(None, true);
            let node = new_node("127.0.0.1:777");
            table.add_node(node.clone(), false);

            let mut limit = NodeIpLimit::new(1);
            limit.init(&table);

            // new node id of same ip
            let entry = new_entry(None, "127.0.0.1:999");
            assert_eq!(
                limit.validate_insertion(&table, &entry),
                InsertResult::IpLimited
            );

            // new node id of new ip
            let entry = new_entry(None, "127.0.0.2:999");
            assert_eq!(
                limit.validate_insertion(&table, &entry),
                InsertResult::Added
            );

            // same node id of same ip
            let entry = new_entry(Some(node.id.clone()), "127.0.0.1:777");
            assert_eq!(
                limit.validate_insertion(&table, &entry),
                InsertResult::Updated
            );

            // same node id of exist ip
            let entry = new_entry(Some(node.id.clone()), "127.0.0.2:777");
            assert_eq!(
                limit.validate_insertion(&table, &entry),
                InsertResult::IpLimited
            );

            // same node id of new ip
            let entry = new_entry(Some(node.id.clone()), "127.0.0.3:777");
            assert_eq!(
                limit.validate_insertion(&table, &entry),
                InsertResult::Updated
            );
        }
    }

    #[cfg(test)]
    mod node_database_tests {
        use super::{
            super::{InsertResult, NodeDatabase},
            new_entry,
        };
        use crate::node_table::NodeId;

        #[test]
        fn test_insert_with_token() {
            let mut db = NodeDatabase::new(None, 1);

            // add a trusted node
            let entry = new_entry(None, "127.0.0.1:999");
            assert_eq!(
                db.insert_trusted(entry.clone()),
                Some(InsertResult::Added)
            );

            // update trusted node
            assert_eq!(
                db.insert_with_token(entry.clone(), 3),
                InsertResult::Updated
            );
            let node = db.get(&entry.id, true);
            assert_eq!(node.is_some(), true);
            assert_eq!(node.unwrap().stream_token, Some(3));

            // add untrusted node
            let entry = new_entry(None, "127.0.0.2:999");
            assert_eq!(
                db.insert_with_token(entry.clone(), 5),
                InsertResult::Added
            );
            assert_eq!(db.get(&entry.id, true), None);
            assert_eq!(db.get(&entry.id, false).unwrap().stream_token, Some(5));

            // update untrusted node, change endpoint and stream token
            let entry = new_entry(Some(entry.id), "127.0.0.2:888");
            assert_eq!(
                db.insert_with_token(entry.clone(), 6),
                InsertResult::Updated
            );
            assert_eq!(db.get(&entry.id, true), None);
            let node = db.get(&entry.id, false).unwrap();
            assert_eq!(node.endpoint, entry.endpoint); // endpoint updated
            assert_eq!(node.stream_token, Some(6)); // stream token updated
        }

        #[test]
        fn test_insert_with_promotion() {
            let mut db = NodeDatabase::new(None, 1);

            // add untrusted node
            let entry = new_entry(None, "127.0.0.1:999");
            assert_eq!(db.insert(entry.clone()), InsertResult::Added);
            assert_eq!(db.get(&entry.id, true), None);
            assert_eq!(db.get(&entry.id, false).is_some(), true);

            // update node and promote
            assert_eq!(
                db.insert_with_promotion(entry.clone()),
                InsertResult::Updated
            );
            assert_eq!(db.get(&entry.id, true).is_some(), true);
        }

        #[test]
        fn test_insert_trusted() {
            let mut db = NodeDatabase::new(None, 1);

            // new added
            let entry = new_entry(None, "127.0.0.1:999");
            assert_eq!(
                db.insert_trusted(entry.clone()),
                Some(InsertResult::Added)
            );
            assert_eq!(db.get(&entry.id, true).is_some(), true);

            // already exists
            assert_eq!(db.insert_trusted(entry.clone()), None);

            // prepare untrusted node to promote
            let entry = new_entry(None, "127.0.0.2:999");
            assert_eq!(db.insert(entry.clone()), InsertResult::Added);
            assert_eq!(db.get(&entry.id, true), None);
            assert_eq!(db.get(&entry.id, false).is_some(), true);

            // add trusted node to promote
            assert_eq!(
                db.insert_trusted(entry.clone()),
                Some(InsertResult::Updated)
            );
            assert_eq!(db.get(&entry.id, true).is_some(), true);
        }

        #[test]
        fn test_remove() {
            let mut db = NodeDatabase::new(None, 1);

            // add trusted node
            let entry1 = new_entry(None, "127.0.0.1:999");
            assert_eq!(
                db.insert_trusted(entry1.clone()),
                Some(InsertResult::Added)
            );

            // add untrusted node
            let entry2 = new_entry(None, "127.0.0.2:999");
            assert_eq!(
                db.insert_with_token(entry2.clone(), 9),
                InsertResult::Added
            );

            assert_eq!(db.ip_limit.ip_to_nodes.len(), 2);

            // delete nodes
            assert_eq!(db.remove(&NodeId::random()), None);
            assert_eq!(db.remove(&entry1.id).is_some(), true);
            assert_eq!(db.remove(&entry2.id).is_some(), true);

            assert_eq!(db.ip_limit.ip_to_nodes.len(), 0);
        }

        #[test]
        fn test_demote() {
            let mut db = NodeDatabase::new(None, 1);

            // add a trusted node
            let entry = new_entry(None, "127.0.0.1:999");
            assert_eq!(
                db.insert_trusted(entry.clone()),
                Some(InsertResult::Added)
            );

            // demote the trusted node to untrusted
            db.demote(&entry.id);
            assert_eq!(db.get(&entry.id, true), None);
            assert!(db.get(&entry.id, false).is_some());
        }
    }
}
