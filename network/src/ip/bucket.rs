use crate::{
    ip::sample::SampleHashSet,
    node_database::NodeDatabase,
    node_table::{NodeContact, NodeId},
};
use rand::{prelude::ThreadRng, thread_rng, Rng};
use std::time::Duration;

/// NodeBucket is used to manage the nodes that grouped by subnet,
/// and support to sample any node from bucket in O(1) time complexity.
#[derive(Default, Debug)]
pub struct NodeBucket {
    nodes: SampleHashSet<NodeId>,
}

impl NodeBucket {
    #[inline]
    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    #[inline]
    pub fn add(&mut self, id: NodeId) -> bool {
        self.nodes.insert(id)
    }

    #[inline]
    pub fn remove(&mut self, id: &NodeId) -> bool {
        self.nodes.remove(id)
    }

    #[inline]
    pub fn sample(&self, rng: &mut ThreadRng) -> Option<NodeId> {
        self.nodes.sample(rng)
    }

    /// Select a node to evict due to bucket is full. The basic priority is as
    /// following:
    /// - Do not evict connecting nodes.
    /// - Evict nodes that have not been contacted for a long time.
    /// - Randomly pick a node without "fresher" bias.
    pub fn select_evictee(
        &self, db: &NodeDatabase, evict_timeout: Duration,
    ) -> Option<NodeId> {
        let mut long_time_nodes = Vec::new();
        let mut evictable_nodes = Vec::new();

        for id in self.nodes.iter() {
            if let Some(node) = db.get(id, false /* trusted_only */) {
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

    #[test]
    fn test_add_remove() {
        let mut bucket = NodeBucket::default();
        assert_eq!(bucket.count(), 0);

        // succeed to add n1
        let n1 = NodeId::random();
        assert_eq!(bucket.add(n1.clone()), true);
        assert_eq!(bucket.count(), 1);

        // cannot add n1 again
        assert_eq!(bucket.add(n1.clone()), false);
        assert_eq!(bucket.count(), 1);

        // succeed to add n2
        let n2 = NodeId::random();
        assert_eq!(bucket.add(n2.clone()), true);
        assert_eq!(bucket.count(), 2);

        // failed to remove non-exist node n3
        let n3 = NodeId::random();
        assert_eq!(bucket.remove(&n3), false);

        // succeed to remove existing n1/n2
        assert_eq!(bucket.remove(&n1), true);
        assert_eq!(bucket.count(), 1);

        assert_eq!(bucket.remove(&n2), true);
        assert_eq!(bucket.count(), 0);
    }

    #[test]
    fn test_sample() {
        let mut bucket = NodeBucket::default();
        let mut rng = thread_rng();

        // sample None if bucket is empty
        assert_eq!(bucket.sample(&mut rng), None);

        // sample any trusted node
        let n1 = NodeId::random();
        assert_eq!(bucket.add(n1.clone()), true);
        assert_eq!(bucket.sample(&mut rng), Some(n1.clone()));
    }
}
