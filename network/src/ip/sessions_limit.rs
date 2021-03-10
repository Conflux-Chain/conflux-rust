use crate::ip::util::SubnetType;
use std::{
    collections::HashMap, convert::TryFrom, hash::Hash, net::IpAddr,
    str::FromStr,
};

/// SessionIpLimit is used to limits the number of sessions for a single IP
/// address or subnet.
pub trait SessionIpLimit: Send + Sync {
    fn contains(&self, _ip: &IpAddr) -> bool {
        true
    }
    fn is_allowed(&self, _ip: &IpAddr) -> bool {
        true
    }
    fn add(&mut self, _ip: IpAddr) -> bool {
        true
    }
    fn remove(&mut self, _ip: &IpAddr) -> bool {
        true
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct SessionIpLimitConfig {
    single_ip_quota: usize,
    subnet_a_quota: usize,
    subnet_b_quota: usize,
    subnet_c_quota: usize,
}

impl TryFrom<String> for SessionIpLimitConfig {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        let configs: Vec<&str> = value.split(',').collect();

        let mut nums = Vec::new();
        for s in configs {
            let num = usize::from_str(s)
                .map_err(|e| format!("failed to parse number: {:?}", e))?;
            nums.push(num);
        }

        if nums.len() != 4 {
            return Err(format!(
                "invalid number of fields, expected = 4, actual = {}",
                nums.len()
            ));
        }

        Ok(SessionIpLimitConfig {
            single_ip_quota: nums[0],
            subnet_a_quota: nums[1],
            subnet_b_quota: nums[2],
            subnet_c_quota: nums[3],
        })
    }
}

/// Creates a SessionIpLimit instance with specified IP quotas. The
/// `subnet_quotas` represents subnet-a (ip/8), subnet-b (ip/16) and subnet-c
/// (ip/24) respectively.
pub fn new_session_ip_limit(
    config: &SessionIpLimitConfig,
) -> Box<dyn SessionIpLimit> {
    let mut limits: Vec<Box<dyn SessionIpLimit>> = Vec::new();

    if config.single_ip_quota > 0 {
        limits.push(Box::new(SingleIpLimit::new(config.single_ip_quota)));
    }

    if config.subnet_a_quota > 0 {
        limits.push(Box::new(SubnetLimit::new(
            config.subnet_a_quota,
            SubnetType::A,
        )));
    }

    if config.subnet_b_quota > 0 {
        limits.push(Box::new(SubnetLimit::new(
            config.subnet_b_quota,
            SubnetType::B,
        )));
    }

    if config.subnet_c_quota > 0 {
        limits.push(Box::new(SubnetLimit::new(
            config.subnet_c_quota,
            SubnetType::C,
        )));
    }

    if limits.is_empty() {
        Box::new(NoopLimit)
    } else {
        Box::new(CompositeLimit::new(limits))
    }
}

struct NoopLimit;
impl SessionIpLimit for NoopLimit {}

struct GenericLimit<T> {
    quota: usize,
    items: HashMap<T, usize>,
}

impl<T: Hash + Eq> GenericLimit<T> {
    fn new(quota: usize) -> Self {
        assert!(quota > 0);

        GenericLimit {
            quota,
            items: HashMap::new(),
        }
    }

    fn contains(&self, key: &T) -> bool {
        self.items.contains_key(key)
    }

    fn is_allowed(&self, key: &T) -> bool {
        match self.items.get(key) {
            Some(num) => *num < self.quota,
            None => true,
        }
    }

    fn add(&mut self, key: T) -> bool {
        match self.items.get_mut(&key) {
            Some(num) => {
                if *num < self.quota {
                    *num += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                self.items.insert(key, 1);
                true
            }
        }
    }

    fn remove(&mut self, key: &T) -> bool {
        let num = match self.items.get_mut(key) {
            Some(num) => num,
            None => return false,
        };

        if *num > 1 {
            *num -= 1;
        } else {
            self.items.remove(key);
        }

        true
    }
}

struct SingleIpLimit {
    inner: GenericLimit<IpAddr>,
}

impl SingleIpLimit {
    fn new(quota: usize) -> Self {
        SingleIpLimit {
            inner: GenericLimit::new(quota),
        }
    }
}

impl SessionIpLimit for SingleIpLimit {
    fn contains(&self, ip: &IpAddr) -> bool {
        self.inner.contains(ip)
    }

    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.inner.is_allowed(ip)
    }

    fn add(&mut self, ip: IpAddr) -> bool {
        self.inner.add(ip)
    }

    fn remove(&mut self, ip: &IpAddr) -> bool {
        self.inner.remove(ip)
    }
}

struct SubnetLimit {
    inner: GenericLimit<u32>,
    subnet_type: SubnetType,
}

impl SubnetLimit {
    fn new(quota: usize, subnet_type: SubnetType) -> Self {
        SubnetLimit {
            inner: GenericLimit::new(quota),
            subnet_type,
        }
    }
}

impl SessionIpLimit for SubnetLimit {
    fn contains(&self, ip: &IpAddr) -> bool {
        let subnet = self.subnet_type.subnet(ip);
        self.inner.contains(&subnet)
    }

    fn is_allowed(&self, ip: &IpAddr) -> bool {
        let subnet = self.subnet_type.subnet(ip);
        self.inner.is_allowed(&subnet)
    }

    fn add(&mut self, ip: IpAddr) -> bool {
        let subnet = self.subnet_type.subnet(&ip);
        self.inner.add(subnet)
    }

    fn remove(&mut self, ip: &IpAddr) -> bool {
        let subnet = self.subnet_type.subnet(ip);
        self.inner.remove(&subnet)
    }
}

struct CompositeLimit {
    limits: Vec<Box<dyn SessionIpLimit>>,
}

impl CompositeLimit {
    fn new(limits: Vec<Box<dyn SessionIpLimit>>) -> Self {
        CompositeLimit { limits }
    }
}

impl SessionIpLimit for CompositeLimit {
    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.limits.iter().all(|l| l.is_allowed(ip))
    }

    fn add(&mut self, ip: IpAddr) -> bool {
        if !self.is_allowed(&ip) {
            return false;
        }

        for limit in self.limits.iter_mut() {
            assert!(limit.add(ip));
        }

        true
    }

    fn remove(&mut self, ip: &IpAddr) -> bool {
        if self.limits.iter().any(|l| !l.contains(ip)) {
            return false;
        }

        for limit in self.limits.iter_mut() {
            assert!(limit.remove(ip));
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::{new_session_ip_limit, SessionIpLimit};
    use std::{convert::TryInto, net::IpAddr, str::FromStr};

    fn new_ip(ip: &'static str) -> IpAddr {
        IpAddr::from_str(ip).unwrap()
    }

    fn new_limit(config: &str) -> Box<dyn SessionIpLimit> {
        let config: String = config.into();
        new_session_ip_limit(&config.try_into().unwrap())
    }

    #[test]
    fn test_noop() {
        let mut limit = new_limit("0,0,0,0");
        assert_eq!(limit.is_allowed(&new_ip("127.0.0.1")), true);
        assert_eq!(limit.add(new_ip("127.0.0.1")), true);
        assert_eq!(limit.remove(&new_ip("127.0.0.2")), true);
    }

    #[test]
    fn test_single_ip() {
        let mut limit = new_limit("1,0,0,0");

        assert_eq!(limit.remove(&new_ip("127.0.0.1")), false);

        assert_eq!(limit.is_allowed(&new_ip("127.0.0.1")), true);
        assert_eq!(limit.add(new_ip("127.0.0.1")), true);

        assert_eq!(limit.is_allowed(&new_ip("127.0.0.1")), false);
        assert_eq!(limit.add(new_ip("127.0.0.1")), false);

        assert_eq!(limit.is_allowed(&new_ip("127.0.0.2")), true);
        assert_eq!(limit.add(new_ip("127.0.0.2")), true);
    }

    #[test]
    fn test_subnet_all() {
        let mut limit = new_limit("0,3,2,1");

        assert_eq!(limit.add(new_ip("127.0.0.1")), true);

        // subnet c
        assert_eq!(limit.add(new_ip("127.0.0.2")), false);

        // subnet b
        assert_eq!(limit.add(new_ip("127.0.1.1")), true);
        assert_eq!(limit.add(new_ip("127.0.1.1")), false);
        assert_eq!(limit.add(new_ip("127.0.1.2")), false);
        assert_eq!(limit.add(new_ip("127.0.2.1")), false);

        // subnet a
        assert_eq!(limit.add(new_ip("192.168.0.1")), true);
        assert_eq!(limit.add(new_ip("192.169.0.1")), true);
        assert_eq!(limit.add(new_ip("192.170.0.1")), true);
        assert_eq!(limit.add(new_ip("192.171.0.1")), false);
    }

    #[test]
    fn test_subnet_b() {
        let mut limit = new_limit("0,0,2,0");

        assert_eq!(limit.add(new_ip("127.0.0.1")), true);
        assert_eq!(limit.add(new_ip("127.0.0.2")), true);
        assert_eq!(limit.add(new_ip("127.0.0.3")), false);
        assert_eq!(limit.add(new_ip("127.0.1.1")), false);
        assert_eq!(limit.add(new_ip("127.1.0.1")), true);
        assert_eq!(limit.add(new_ip("127.2.0.1")), true);
        assert_eq!(limit.add(new_ip("127.3.0.1")), true);
    }
}
