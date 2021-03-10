use std::{convert::TryFrom, net::IpAddr};

#[derive(Debug)]
pub enum SubnetType {
    A, // a.xxx.xxx.xxx/8
    B, // a.b.xxx.xxx/16
    C, // a.b.c.xxx/24
}

impl SubnetType {
    pub fn subnet(&self, ip: &IpAddr) -> u32 {
        match *self {
            SubnetType::A => SubnetType::calc_subnet(ip, 8),
            SubnetType::B => SubnetType::calc_subnet(ip, 16),
            SubnetType::C => SubnetType::calc_subnet(ip, 24),
        }
    }

    fn calc_subnet(ip: &IpAddr, prefix_bits: usize) -> u32 {
        match ip {
            IpAddr::V4(ipv4) => {
                let num: u32 = ipv4.clone().into();
                num >> (32 - prefix_bits)
            }
            IpAddr::V6(ipv6) => {
                let num: u128 = ipv6.clone().into();
                (num >> (128 - prefix_bits)) as u32
            }
        }
    }
}

impl TryFrom<usize> for SubnetType {
    type Error = String;

    fn try_from(value: usize) -> Result<Self, String> {
        match value {
            8 => Ok(SubnetType::A),
            16 => Ok(SubnetType::B),
            24 => Ok(SubnetType::C),
            _ => Err("Valid subnet prefix bits are 8, 16 and 24".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SubnetType;
    use std::{net::IpAddr, str::FromStr};

    fn new_ip(ip: &'static str) -> IpAddr {
        IpAddr::from_str(ip).unwrap()
    }

    #[test]
    fn test_subnet() {
        assert_eq!(
            SubnetType::C.subnet(&new_ip("127.0.0.1")),
            SubnetType::C.subnet(&new_ip("127.0.0.2"))
        );
        assert_ne!(
            SubnetType::C.subnet(&new_ip("127.0.0.1")),
            SubnetType::C.subnet(&new_ip("127.0.1.1"))
        );

        assert_eq!(
            SubnetType::B.subnet(&new_ip("127.0.0.1")),
            SubnetType::B.subnet(&new_ip("127.0.0.2"))
        );
        assert_eq!(
            SubnetType::B.subnet(&new_ip("127.0.0.1")),
            SubnetType::B.subnet(&new_ip("127.0.1.1"))
        );
        assert_ne!(
            SubnetType::B.subnet(&new_ip("127.0.0.1")),
            SubnetType::B.subnet(&new_ip("127.1.0.1"))
        );

        assert_eq!(
            SubnetType::A.subnet(&new_ip("127.0.0.1")),
            SubnetType::A.subnet(&new_ip("127.0.0.2"))
        );
        assert_eq!(
            SubnetType::A.subnet(&new_ip("127.0.0.1")),
            SubnetType::A.subnet(&new_ip("127.0.1.1"))
        );
        assert_eq!(
            SubnetType::A.subnet(&new_ip("127.0.0.1")),
            SubnetType::A.subnet(&new_ip("127.1.0.1"))
        );
        assert_ne!(
            SubnetType::A.subnet(&new_ip("127.0.0.1")),
            SubnetType::A.subnet(&new_ip("192.0.0.1"))
        );
    }
}
