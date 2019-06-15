// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::node_table::NodeId;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::IpAddr,
};

pub type SessionIpLimit = IpLimit<usize>;
pub type NodeIpLimit = IpLimit<NodeId>;

/// IP address limitation for sessions or nodes.
pub struct IpLimit<KEY> {
    quota: usize, // 0 presents unlimited
    ip_to_keys: HashMap<IpAddr, HashSet<KEY>>,
}

impl<KEY: Hash + Eq> IpLimit<KEY> {
    pub fn new(quota: usize) -> Self {
        IpLimit {
            quota,
            ip_to_keys: HashMap::new(),
        }
    }

    #[inline]
    pub fn get_quota(&self) -> usize { self.quota }

    #[inline]
    pub fn is_enabled(&self) -> bool { self.quota > 0 }

    /// Check if the specified IP address is allowed.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        if !self.is_enabled() {
            return true;
        }

        match self.ip_to_keys.get(ip) {
            Some(keys) => keys.len() < self.quota,
            None => true,
        }
    }

    /// Validate IP address when adding a new node.
    pub fn on_add(&mut self, ip: IpAddr, key: KEY) -> bool {
        if !self.is_enabled() {
            return true;
        }

        if !self.is_ip_allowed(&ip) {
            return false;
        }

        if let Some(keys) = self.ip_to_keys.get(&ip) {
            if keys.contains(&key) {
                return false;
            }
        }

        self.ip_to_keys
            .entry(ip)
            .or_insert_with(|| HashSet::new())
            .insert(key)
    }

    /// Update the number of nodes for the specified IP address when deleting a
    /// node.
    pub fn on_delete(&mut self, ip: &IpAddr, key: &KEY) -> bool {
        if !self.is_enabled() {
            return true;
        }

        let keys = match self.ip_to_keys.get_mut(ip) {
            Some(keys) => keys,
            None => return false,
        };

        if !keys.remove(key) {
            return false;
        }

        if keys.is_empty() {
            self.ip_to_keys.remove(ip);
        }

        true
    }

    pub fn get_keys(&self, ip: &IpAddr) -> Option<&HashSet<KEY>> {
        self.ip_to_keys.get(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::SessionIpLimit;
    use std::{net::IpAddr, str::FromStr};

    fn new_ip(ip: &str) -> IpAddr { IpAddr::from_str(ip).unwrap() }

    #[test]
    fn test_enabled() {
        assert_eq!(SessionIpLimit::new(0).is_enabled(), false);
        assert_eq!(SessionIpLimit::new(1).is_enabled(), true);
        assert_eq!(SessionIpLimit::new(4).is_enabled(), true);

        let mut limit = SessionIpLimit::new(0);
        let ip = new_ip("127.0.0.1");
        assert_eq!(limit.on_add(ip, 1), true);
        assert_eq!(limit.on_add(ip, 2), true);
        assert_eq!(limit.on_add(ip, 3), true);
    }

    #[test]
    fn test_on_add() {
        let mut limit = SessionIpLimit::new(2);
        let ip = new_ip("127.0.0.1");

        assert_eq!(limit.is_ip_allowed(&ip), true);
        assert_eq!(limit.on_add(ip, 1), true);

        assert_eq!(limit.is_ip_allowed(&ip), true);
        assert_eq!(limit.on_add(ip, 1), false); // duplicated key
        assert_eq!(limit.on_add(ip, 2), true);

        assert_eq!(limit.is_ip_allowed(&ip), false);
        assert_eq!(limit.on_add(ip, 3), false);
    }

    #[test]
    fn test_on_delete() {
        let mut limit = SessionIpLimit::new(2);
        let ip = new_ip("127.0.0.1");

        assert_eq!(limit.on_add(ip, 1), true);
        assert_eq!(limit.on_add(ip, 2), true);
        assert_eq!(limit.get_keys(&ip).unwrap().len(), 2);

        assert_eq!(limit.on_delete(&ip, &3), false); // invalid key
        assert_eq!(limit.on_delete(&ip, &2), true);
        assert_eq!(limit.get_keys(&ip).unwrap().len(), 1);
        assert_eq!(limit.on_delete(&ip, &1), true);
        assert_eq!(limit.get_keys(&ip), None);
    }
}
