use crate::{
    node_database::NodeDatabase,
    node_table::{NodeContact, NodeId},
};
use rand::{thread_rng, Rng, ThreadRng};
use std::{collections::HashMap, slice::Iter, time::Duration};

/// NodeBucket is used to manage the nodes that grouped by subnet,
/// and support to sample any node from bucket.
#[derive(Default, Debug)]
pub struct NodeBucket {
    subnet: u32,

    // use HashMap + Vec for O(1) query and O(1) sample
    trusted_nodes: Vec<NodeId>,
    trusted_index: HashMap<NodeId, usize>,

    untrusted_nodes: Vec<NodeId>,
    untrusted_index: HashMap<NodeId, usize>,
}

impl NodeBucket {
    pub fn new(subnet: u32) -> Self {
        let mut bucket = NodeBucket::default();
        bucket.subnet = subnet;
        bucket
    }

    #[inline]
    pub fn subnet(&self) -> u32 { self.subnet }

    #[inline]
    pub fn count(&self) -> usize {
        self.trusted_nodes.len() + self.untrusted_nodes.len()
    }

    #[inline]
    fn contains(&self, id: &NodeId) -> bool {
        self.trusted_index.contains_key(id)
            || self.untrusted_index.contains_key(id)
    }

    /// Add the specified node `id` into bucket as trusted or untrusted.
    /// Return `true` if new added, otherwise `false`.
    pub fn add(&mut self, id: NodeId, trusted: bool) -> bool {
        if self.contains(&id) {
            return false;
        }

        if trusted {
            self.trusted_index
                .insert(id.clone(), self.trusted_nodes.len());
            self.trusted_nodes.push(id);
        } else {
            self.untrusted_index
                .insert(id.clone(), self.untrusted_nodes.len());
            self.untrusted_nodes.push(id);
        }

        true
    }

    /// Remove the specified node `id` from bucket.
    /// Return `false` if node not found, otherwise `true`.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        if let Some(index) = self.trusted_index.remove(id) {
            self.trusted_nodes.swap_remove(index);

            if let Some(node) = self.trusted_nodes.get(index) {
                self.trusted_index.insert(node.clone(), index);
            }

            true
        } else if let Some(index) = self.untrusted_index.remove(id) {
            self.untrusted_nodes.swap_remove(index);

            if let Some(node) = self.untrusted_nodes.get(index) {
                self.untrusted_index.insert(node.clone(), index);
            }

            true
        } else {
            false
        }
    }

    /// Randomly select a node with the specified `rng` if bucket is not empty.
    pub fn sample_trusted(&self, rng: &mut ThreadRng) -> Option<NodeId> {
        if self.trusted_nodes.is_empty() {
            return None;
        }

        let index = rng.gen_range(0, self.trusted_nodes.len());
        Some(self.trusted_nodes[index].clone())
    }

    /// Select a node to evict due to bucket is full. The basic priority is as
    /// following:
    /// - Evict untrusted nodes prior to trusted ones.
    /// - Do not evict connecting nodes.
    /// - Evict nodes that have not been contacted for a long time.
    /// - Randomly pick a node without "fresher" bias.
    pub fn select_evictee(
        &self, db: &NodeDatabase, evict_timeout: Duration,
    ) -> Option<NodeId> {
        self.select_evictee_with_nodes(
            self.untrusted_nodes.iter(),
            db,
            evict_timeout,
        )
        .or_else(|| {
            self.select_evictee_with_nodes(
                self.trusted_nodes.iter(),
                db,
                evict_timeout,
            )
        })
    }

    fn select_evictee_with_nodes(
        &self, nodes: Iter<NodeId>, db: &NodeDatabase, evict_timeout: Duration,
    ) -> Option<NodeId> {
        let mut long_time_nodes = Vec::new();
        let mut evictable_nodes = Vec::new();

        for id in nodes {
            if let Some((_, node)) = db.get_with_trusty(id) {
                // do not evict the connecting nodes
                if let Some(NodeContact::Success(_)) = node.last_connected {
                    continue;
                }

                match node.last_contact {
                    Some(contact) => match contact.time().elapsed() {
                        Ok(d) => {
                            if d > evict_timeout {
                                long_time_nodes.push(id);
                            } else {
                                evictable_nodes.push(id);
                            }
                        }
                        Err(_) => long_time_nodes.push(id),
                    },
                    None => long_time_nodes.push(id),
                }
            }
        }

        let mut rng = thread_rng();

        // evict out-of-date node with high priority
        if !long_time_nodes.is_empty() {
            let index = rng.gen_range(0, long_time_nodes.len());
            return Some(long_time_nodes[index].clone());
        }

        // randomly evict one
        if !evictable_nodes.is_empty() {
            let index = rng.gen_range(0, evictable_nodes.len());
            return Some(evictable_nodes[index].clone());
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeBucket, NodeId};
    use rand::thread_rng;

    fn assert_node_with_trusty(
        bucket: &NodeBucket, id: &NodeId, trusted: bool,
    ) {
        if trusted {
            assert_eq!(bucket.untrusted_index.contains_key(id), false);
            assert_eq!(bucket.trusted_index.contains_key(id), true);
            let index = bucket.trusted_index[id];
            assert_eq!(&bucket.trusted_nodes[index], id);
        } else {
            assert_eq!(bucket.trusted_index.contains_key(id), false);
            assert_eq!(bucket.untrusted_index.contains_key(id), true);
            let index = bucket.untrusted_index[id];
            assert_eq!(&bucket.untrusted_nodes[index], id);
        }
    }

    #[test]
    fn test_add_remove() {
        let mut bucket = NodeBucket::new(0);
        assert_eq!(bucket.count(), 0);

        // add n1 as trusted
        let n1 = NodeId::random();
        assert_eq!(bucket.add(n1.clone(), true), true);
        assert_node_with_trusty(&bucket, &n1, true);
        assert_eq!(bucket.count(), 1);

        // cannot add n1 again
        assert_eq!(bucket.add(n1.clone(), true), false);
        assert_eq!(bucket.add(n1.clone(), false), false);

        // add n2 as trusted
        let n2 = NodeId::random();
        assert_eq!(bucket.add(n2.clone(), true), true);
        assert_node_with_trusty(&bucket, &n2, true);
        assert_eq!(bucket.count(), 2);

        // add n3 as untrusted
        let n3 = NodeId::random();
        assert_eq!(bucket.add(n3.clone(), false), true);
        assert_node_with_trusty(&bucket, &n3, false);
        assert_eq!(bucket.count(), 3);

        // remove non-exist node
        let n4 = NodeId::random();
        assert_eq!(bucket.remove(&n4), false);

        // remove existing n1/n2/n3
        assert_eq!(bucket.remove(&n1), true);
        assert_eq!(bucket.contains(&n1), false);
        assert_eq!(bucket.count(), 2);

        assert_eq!(bucket.remove(&n2), true);
        assert_eq!(bucket.contains(&n2), false);
        assert_eq!(bucket.count(), 1);

        assert_eq!(bucket.remove(&n3), true);
        assert_eq!(bucket.contains(&n3), false);
        assert_eq!(bucket.count(), 0);
    }

    #[test]
    fn test_sample() {
        let mut bucket = NodeBucket::new(0);
        let mut rng = thread_rng();

        // sample None if bucket is empty
        assert_eq!(bucket.sample_trusted(&mut rng), None);

        // sample any trusted node
        let n1 = NodeId::random();
        assert_eq!(bucket.add(n1.clone(), true), true);
        assert_eq!(bucket.sample_trusted(&mut rng), Some(n1.clone()));

        // cannot sample from untrusted node
        assert_eq!(bucket.remove(&n1), true);
        let n2 = NodeId::random();
        assert_eq!(bucket.add(n2.clone(), false), true);
        assert_eq!(bucket.sample_trusted(&mut rng), None);
    }
}
