// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    ip::{
        sample::{SampleHashMap, SampleHashSet},
        util::SubnetType,
    },
    node_table::{NodeId, NodeTable},
    Node,
};
use rand::thread_rng;
use std::collections::{HashMap, HashSet};

/// Tag based node index, so as to filter nodes by tag in node database.
/// It support to sample nodes with special tag in O(1) time complexity.
#[derive(Default)]
pub struct NodeTagIndex {
    // map<tag_key, map<tag_value, map<subnet, set<node_id>>>>
    items: HashMap<
        String,
        HashMap<String, SampleHashMap<u32, SampleHashSet<NodeId>>>,
    >,
}

impl NodeTagIndex {
    /// Build the node tag based index for the specified node table.
    pub fn new_with_node_table(table: &NodeTable) -> Self {
        let mut result = NodeTagIndex::default();

        for id in table.all() {
            let node = table.get(&id).expect("node not found in table");
            for (k, v) in node.tags.iter() {
                let ip = node.endpoint.address.ip();
                let subnet = SubnetType::C.subnet(&ip);
                result.insert(id, subnet, k.clone(), v.clone());
            }
        }

        result
    }

    pub fn insert(
        &mut self, id: NodeId, subnet: u32, key: String, value: String,
    ) -> bool {
        self.items
            .entry(key)
            .or_insert_with(Default::default)
            .entry(value)
            .or_insert_with(Default::default)
            .get_mut_or_insert_with(subnet, Default::default)
            .insert(id)
    }

    pub fn remove(
        &mut self, id: &NodeId, subnet: u32, key: &String, value: &String,
    ) -> Option<()> {
        let tag_key_values = self.items.get_mut(key)?;
        let buckets = tag_key_values.get_mut(value)?;
        let nodes = buckets.get_mut(&subnet)?;

        if !nodes.remove(id) {
            return None;
        }

        if nodes.is_empty() {
            buckets.remove(&subnet);
        }

        if buckets.is_empty() {
            tag_key_values.remove(value);
        }

        if tag_key_values.is_empty() {
            self.items.remove(key);
        }

        Some(())
    }

    pub fn sample(
        &self, count: u32, key: &String, value: &String,
    ) -> Option<HashSet<NodeId>> {
        let buckets = self.items.get(key)?.get(value)?;

        let mut rng = thread_rng();
        let mut sampled = HashSet::new();

        for _ in 0..count {
            if let Some(bucket) = buckets.sample(&mut rng) {
                if let Some(id) = bucket.sample(&mut rng) {
                    sampled.insert(id);
                }
            }
        }

        Some(sampled)
    }

    pub fn add_node(&mut self, node: &Node) {
        if node.tags.is_empty() {
            return;
        }

        let ip = node.endpoint.address.ip();
        let subnet = SubnetType::C.subnet(&ip);

        for (key, value) in node.tags.iter() {
            self.insert(node.id.clone(), subnet, key.clone(), value.clone());
        }
    }

    pub fn remove_node(&mut self, node: &Node) {
        if node.tags.is_empty() {
            return;
        }

        let ip = node.endpoint.address.ip();
        let subnet = SubnetType::C.subnet(&ip);

        for (key, value) in node.tags.iter() {
            self.remove(&node.id, subnet, key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ip::NodeTagIndex, node_table::NodeId};

    #[test]
    fn test_insert() {
        let mut index = NodeTagIndex::default();

        let n1 = NodeId::random();
        assert_eq!(
            index.insert(n1.clone(), 38, "k1".into(), "v1".into()),
            true
        );
        assert_eq!(
            index.insert(n1.clone(), 38, "k1".into(), "v1".into()),
            false
        );
        assert_eq!(
            index.insert(n1.clone(), 38, "k1".into(), "v2".into()),
            true
        );
        assert_eq!(
            index.insert(n1.clone(), 38, "k2".into(), "v1".into()),
            true
        );
        assert_eq!(
            index.insert(n1.clone(), 39, "k1".into(), "v1".into()),
            true
        );
        assert_eq!(
            index.insert(NodeId::random(), 38, "k1".into(), "v1".into()),
            true
        );
    }

    #[test]
    fn test_remove() {
        let mut index = NodeTagIndex::default();

        let n1 = NodeId::random();
        assert_eq!(
            index.insert(n1.clone(), 38, "k1".into(), "v1".into()),
            true
        );

        let n2 = NodeId::random();
        assert_eq!(index.remove(&n2, 38, &"k1".into(), &"v1".into()), None);
        assert_eq!(index.remove(&n1, 39, &"k1".into(), &"v1".into()), None);
        assert_eq!(index.remove(&n1, 38, &"k2".into(), &"v1".into()), None);
        assert_eq!(index.remove(&n1, 38, &"k1".into(), &"v2".into()), None);
        assert_eq!(index.remove(&n1, 38, &"k1".into(), &"v1".into()), Some(()));
    }

    #[test]
    fn test_sample() {
        let mut index = NodeTagIndex::default();

        // sample nothing on empty
        assert_eq!(index.sample(10, &"k1".into(), &"v1".into()), None);

        // add index and sampled 1 node.
        let n1 = NodeId::random();
        assert_eq!(
            index.insert(n1.clone(), 38, "k1".into(), "v1".into()),
            true
        );
        let sampled = index.sample(1, &"k1".into(), &"v1".into());
        assert_eq!(sampled.unwrap().into_iter().next(), Some(n1));
    }
}
