use crate::{
    ip::{bucket::NodeBucket, sample::SampleHashMap, util::SubnetType},
    node_database::NodeDatabase,
    node_table::NodeId,
};
use rand::thread_rng;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

/// Default maximum duration of last node contact time that used to evict a node
/// when `NodeBucket` is full.
const DEFAULT_EVICT_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 3600); // 7 days

/// Validation result before adding a node.
#[derive(Debug, PartialEq)]
pub enum ValidateInsertResult {
    /// Node already exists and IP address not changed
    AlreadyExists,
    /// Node will be new added, and occupy the IP address used by existing
    /// node. In this case, the existing node will be evicted before adding
    /// the new node.
    OccupyIp(NodeId),
    /// Node is allowed to add or update with new IP address, because the
    /// corresponding `NodeBucket` has enough quota.
    QuotaEnough,
    /// Node is allowed to add or update, but need to evict the specified
    /// existing node first.
    Evict(NodeId),
    /// Node is not allowed to add or update, because the corresponding
    /// `NodeBucket` is full, and no node could be evicted. E.g. all nodes in
    /// the bucket are in connecting status.
    QuotaNotEnough,
}

/// NodeLimit is used to limit the number of nodes stored in database via IP
/// address and subnet. Basically, one IP address only allow one node stored
/// in database, and a subnet allow configured N nodes stored in database.
///
/// When adding a new node, and the number of nodes for the subnet reaches the
/// quota limitation, any node may be evicted from database according to
/// a pre-defined rule.
#[derive(Debug)]
pub struct NodeIpLimit {
    subnet_type: SubnetType,
    subnet_quota: usize,     // quota for a subnet
    evict_timeout: Duration, // used to evict out-of-date node

    // all trusted nodes grouped by subnet
    trusted_buckets: SampleHashMap<u32, NodeBucket>,
    // all untrusted nodes grouped by subnet
    untrusted_buckets: SampleHashMap<u32, NodeBucket>,

    // helpful indices
    ip_index: HashMap<IpAddr, NodeId>,
    node_index: HashMap<NodeId, IpAddr>,
}

impl NodeIpLimit {
    pub fn new(subnet_quota: usize) -> Self {
        NodeIpLimit {
            subnet_type: SubnetType::C,
            subnet_quota,
            evict_timeout: DEFAULT_EVICT_TIMEOUT,
            trusted_buckets: Default::default(),
            untrusted_buckets: Default::default(),
            ip_index: HashMap::new(),
            node_index: HashMap::new(),
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.subnet_quota > 0
    }

    /// Get the subnet of specified node `id`.
    pub fn subnet(&self, id: &NodeId) -> Option<u32> {
        let ip = self.node_index.get(id)?;
        Some(self.subnet_type.subnet(ip))
    }

    /// Remove the specified node `id` and return `true` if removed
    /// successfully. If not found, return `false`.
    pub fn remove(&mut self, id: &NodeId) -> bool {
        if !self.is_enabled() {
            return true;
        }

        let ip = match self.node_index.remove(id) {
            Some(ip) => ip,
            None => return false,
        };

        self.ip_index.remove(&ip);

        let subnet = self.subnet_type.subnet(&ip);
        if !Self::remove_with_buckets(&mut self.trusted_buckets, subnet, id) {
            Self::remove_with_buckets(&mut self.untrusted_buckets, subnet, id);
        }

        true
    }

    /// Remove node from specified buckets.
    fn remove_with_buckets(
        buckets: &mut SampleHashMap<u32, NodeBucket>, subnet: u32, id: &NodeId,
    ) -> bool {
        let bucket = match buckets.get_mut(&subnet) {
            Some(bucket) => bucket,
            None => return false,
        };

        if !bucket.remove(id) {
            return false;
        }

        // remove bucket on empty
        if bucket.count() == 0 {
            buckets.remove(&subnet);
        }

        true
    }

    /// Randomly select `n` trusted nodes. Note, it may return less than `n`
    /// nodes. Note, the time complexity is O(n), where n is the number of
    /// sampled nodes.
    pub fn sample_trusted(&self, n: u32) -> HashSet<NodeId> {
        if !self.is_enabled() {
            return HashSet::new();
        }

        let mut sampled = HashSet::new();
        if self.trusted_buckets.is_empty() {
            return sampled;
        }

        let mut rng = thread_rng();

        for _ in 0..n {
            if let Some(bucket) = self.trusted_buckets.sample(&mut rng) {
                if let Some(id) = bucket.sample(&mut rng) {
                    sampled.insert(id);
                }
            }
        }

        sampled
    }

    /// Validate before inserting a node with specified `id` and `ip`.
    /// The returned result indicates whether insertion is allowed,
    /// and possible evictee before insertion.
    ///
    /// When subnet quota is not enough before insertion:
    /// 1. If node IP changed and still in the same subnet,
    /// just evict the node itself.
    /// 2. Otherwise, someone in the subnet of `ip` may be evicted.
    ///
    /// There are 2 cases that insertion is not allowed:
    /// 1. Node already exists and ip not changed;
    /// 2. Subnet quota is not enough, and no evictee found.
    pub fn validate_insertion(
        &self, id: &NodeId, ip: &IpAddr, db: &NodeDatabase,
    ) -> ValidateInsertResult {
        if !self.is_enabled() {
            return ValidateInsertResult::QuotaEnough;
        }

        // node exists and ip not changed.
        let maybe_cur_ip = self.node_index.get(&id);
        if let Some(cur_ip) = maybe_cur_ip {
            if cur_ip == ip {
                return ValidateInsertResult::AlreadyExists;
            }
        }

        // ip already in use by other node
        if let Some(old_id) = self.ip_index.get(&ip) {
            return ValidateInsertResult::OccupyIp(old_id.clone());
        }

        // quota enough
        if self.is_quota_allowed(ip) {
            return ValidateInsertResult::QuotaEnough;
        }

        // Node ip changed, but still in the same subnet.
        // So, just evict the node itself.
        if let Some(cur_ip) = maybe_cur_ip {
            let cur_subnet = self.subnet_type.subnet(cur_ip);
            let new_subnet = self.subnet_type.subnet(ip);
            if cur_subnet == new_subnet {
                return ValidateInsertResult::Evict(id.clone());
            }
        }

        // quota not enough, try to evict one.
        if let Some(evictee) = self.select_evictee(ip, db) {
            return ValidateInsertResult::Evict(evictee);
        }

        ValidateInsertResult::QuotaNotEnough
    }

    /// Insert a node with specified `id` and `ip` as trusted or untrusted.
    /// If evictee specified, then remove that one before insert new one.
    /// Returns `true` if insert successfully, otherwise `false`.
    pub fn insert(
        &mut self, id: NodeId, ip: IpAddr, trusted: bool,
        evictee: Option<NodeId>,
    ) -> bool {
        if !self.is_enabled() {
            return true;
        }

        // node exists and ip not changed.
        if let Some(cur_ip) = self.node_index.get(&id) {
            if *cur_ip == ip {
                return false;
            }
        }

        // remove evictee before insertion
        if let Some(id) = evictee {
            self.remove(&id);
        }

        // ip already in use by other node
        if self.ip_index.contains_key(&ip) {
            return false;
        }

        if self.is_quota_allowed(&ip) {
            self.add_or_update(ip, id, trusted);
            return true;
        }

        false
    }

    /// Demote `id` from trusted to untrusted
    pub fn demote(&mut self, id: &NodeId) {
        if let Some(ip) = self.node_index.get(id) {
            let subnet = self.subnet_type.subnet(ip);
            if let Some(b) = self.trusted_buckets.get_mut(&subnet) {
                if b.remove(id) {
                    if let Some(b) = self.untrusted_buckets.get_mut(&subnet) {
                        b.add(id.clone());
                    }
                }
            }
        }
    }

    /// Add or update a node with new IP address. It assumes that the bucket
    /// of corresponding subnet have enough quota.
    fn add_or_update(&mut self, ip: IpAddr, id: NodeId, trusted: bool) {
        // clear the old ip information at first
        self.remove(&id);

        self.node_index.insert(id.clone(), ip);
        self.ip_index.insert(ip, id.clone());

        let subnet = self.subnet_type.subnet(&ip);
        if trusted {
            self.trusted_buckets
                .get_mut_or_insert_with(subnet, NodeBucket::default)
                .add(id);
        } else {
            self.untrusted_buckets
                .get_mut_or_insert_with(subnet, NodeBucket::default)
                .add(id);
        }
    }

    /// Check whether the subnet quota is enough for the specified IP address .
    fn is_quota_allowed(&self, ip: &IpAddr) -> bool {
        let subnet = self.subnet_type.subnet(ip);

        let num_trusted = self
            .trusted_buckets
            .get(&subnet)
            .map_or(0, |bucket| bucket.count());

        let num_untrusted = self
            .untrusted_buckets
            .get(&subnet)
            .map_or(0, |bucket| bucket.count());

        num_trusted + num_untrusted < self.subnet_quota
    }

    /// Select a node to evict.
    fn select_evictee(&self, ip: &IpAddr, db: &NodeDatabase) -> Option<NodeId> {
        let subnet = self.subnet_type.subnet(&ip);

        // evict untrusted node prior to trusted node
        self.untrusted_buckets
            .get(&subnet)
            .and_then(|bucket| bucket.select_evictee(db, self.evict_timeout))
            .or_else(|| {
                self.trusted_buckets.get(&subnet).and_then(|bucket| {
                    bucket.select_evictee(db, self.evict_timeout)
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeDatabase, NodeId, NodeIpLimit, ValidateInsertResult};
    use std::{net::IpAddr, str::FromStr};

    fn new_ip(ip: &'static str) -> IpAddr {
        IpAddr::from_str(ip).unwrap()
    }

    #[test]
    fn test_remove() {
        let mut limit = NodeIpLimit::new(2);

        // remove non-exist node
        assert_eq!(limit.remove(&NodeId::random()), false);

        // add 2 new nodes
        let n1 = NodeId::random();
        let ip1 = new_ip("127.0.0.1");
        assert_eq!(limit.insert(n1.clone(), ip1, true, None), true);

        let n2 = NodeId::random();
        let ip2 = new_ip("127.0.0.2");
        assert_eq!(limit.insert(n2.clone(), ip2, true, None), true);

        // remove those 2 nodes
        validate_node(&limit, &n1, &ip1, true /* exists */);
        assert_eq!(limit.remove(&n1), true);
        validate_node(&limit, &n1, &ip1, false /* exists */);

        validate_node(&limit, &n2, &ip2, true /* exists */);
        assert_eq!(limit.remove(&n2), true);
        validate_node(&limit, &n2, &ip2, false /* exists */);
    }

    #[test]
    fn test_sample() {
        let mut limit = NodeIpLimit::new(2);

        // empty case
        assert_eq!(limit.sample_trusted(3).is_empty(), true);

        // only untrusted nodes case
        let n1 = NodeId::random();
        let ip1 = new_ip("127.0.0.1");
        assert_eq!(limit.insert(n1, ip1, false, None), true);
        assert_eq!(limit.sample_trusted(3).is_empty(), true);

        // trusted nodes case
        let n2 = NodeId::random();
        let ip2 = new_ip("127.0.0.2");
        assert_eq!(limit.insert(n2, ip2, true, None), true);
        assert_eq!(limit.sample_trusted(0).len(), 0);
        assert_eq!(limit.sample_trusted(1).len(), 1);
        assert_eq!(limit.sample_trusted(3).len(), 1);
    }

    fn validate_node(
        limit: &NodeIpLimit, id: &NodeId, ip: &IpAddr, exists: bool,
    ) {
        if !exists {
            assert_eq!(limit.node_index.contains_key(id), false);
        } else {
            assert_eq!(limit.node_index.contains_key(id), true);
            assert_eq!(limit.node_index[id], *ip);
        }
    }

    #[test]
    fn test_insert_duplicate_id_ip() {
        let mut limit = NodeIpLimit::new(2);
        let db = NodeDatabase::new(None, 2);

        // quota is enough
        let n = NodeId::random();
        let ip = new_ip("127.0.0.1");
        assert_eq!(
            limit.validate_insertion(&n, &ip, &db),
            ValidateInsertResult::QuotaEnough
        );
        assert_eq!(limit.insert(n.clone(), ip, true, None), true);
        validate_node(&limit, &n, &ip, true /* exists */);

        // cannot insert with same id and ip as trusted or untrusted
        assert_eq!(
            limit.validate_insertion(&n, &ip, &db),
            ValidateInsertResult::AlreadyExists
        );
        assert_eq!(limit.insert(n.clone(), ip, true, None), false);
        assert_eq!(limit.insert(n.clone(), ip, false, None), false);
        validate_node(&limit, &n, &ip, true /* exists */);
    }

    #[test]
    fn test_insert_occupy_ip_new_node() {
        let mut limit = NodeIpLimit::new(2);
        let db = NodeDatabase::new(None, 2);

        // insert n1
        let n1 = NodeId::random();
        let ip = new_ip("127.0.0.1");
        assert_eq!(
            limit.validate_insertion(&n1, &ip, &db),
            ValidateInsertResult::QuotaEnough
        );
        assert_eq!(limit.insert(n1.clone(), ip, true, None), true);
        validate_node(&limit, &n1, &ip, true /* exists */);

        // add n2 with existing ip which need to evict the n1
        let n2 = NodeId::random();
        assert_eq!(
            limit.validate_insertion(&n2, &ip, &db),
            ValidateInsertResult::OccupyIp(n1.clone())
        );

        // add n2 without evicting n1
        assert_eq!(limit.insert(n2.clone(), ip, true, None), false);
        validate_node(&limit, &n1, &ip, true /* exists */); // n1 not evicted
        validate_node(&limit, &n2, &ip, false /* exists */); // n2 not inserted

        // add n2 with evicting n1
        assert_eq!(limit.insert(n2.clone(), ip, true, Some(n1.clone())), true);
        validate_node(&limit, &n1, &ip, false /* exists */); // n1 evicted
        validate_node(&limit, &n2, &ip, true /* exists */); // n2 inserted
    }

    #[test]
    fn test_insert_occupy_ip_update_node() {
        let mut limit = NodeIpLimit::new(2);
        let db = NodeDatabase::new(None, 2);

        // insert n1 and n2
        let n1 = NodeId::random();
        let ip1 = new_ip("127.0.0.1");
        assert_eq!(
            limit.validate_insertion(&n1, &ip1, &db),
            ValidateInsertResult::QuotaEnough
        );
        assert_eq!(limit.insert(n1.clone(), ip1, true, None), true);
        validate_node(&limit, &n1, &ip1, true /* exists */);

        let n2 = NodeId::random();
        let ip2 = new_ip("127.0.0.2");
        assert_eq!(
            limit.validate_insertion(&n2, &ip2, &db),
            ValidateInsertResult::QuotaEnough
        );
        assert_eq!(limit.insert(n2.clone(), ip2, true, None), true);
        validate_node(&limit, &n2, &ip2, true /* exists */);

        // change n2's ip from ip2 to ip1
        assert_eq!(
            limit.validate_insertion(&n2, &ip1, &db),
            ValidateInsertResult::OccupyIp(n1.clone())
        );

        // update n2 without evicting n1
        assert_eq!(limit.insert(n2.clone(), ip1, true, None), false);
        validate_node(&limit, &n1, &ip1, true /* exists */); // n1 not evicted
        validate_node(&limit, &n2, &ip2, true /* exists */); // n2 not updated

        // update n2 with evicting n1
        assert_eq!(limit.insert(n2.clone(), ip1, true, Some(n1.clone())), true);
        validate_node(&limit, &n1, &ip1, false /* exists */); // n1 evicted
        validate_node(&limit, &n2, &ip1, true /* exists */); // n2 updated
    }

    #[test]
    fn test_is_quota_allowed() {
        let mut limit = NodeIpLimit::new(2);

        // add n1
        let n1 = NodeId::random();
        let ip1 = new_ip("127.0.0.1");
        assert_eq!(limit.insert(n1, ip1, true, None), true);

        // add n2
        let n2 = NodeId::random();
        let ip2 = new_ip("127.0.0.2");
        assert_eq!(limit.insert(n2, ip2, true, None), true);

        // same subnet
        assert_eq!(limit.is_quota_allowed(&new_ip("127.0.0.3")), false);

        // different subnet
        assert_eq!(limit.is_quota_allowed(&new_ip("127.0.1.1")), true);
    }

    #[test]
    fn test_select_evictee() {
        let limit = NodeIpLimit::new(2);
        let db = NodeDatabase::new(None, 2);

        // select from empty bucket
        assert_eq!(limit.select_evictee(&new_ip("127.0.0.1"), &db), None);
    }
}
