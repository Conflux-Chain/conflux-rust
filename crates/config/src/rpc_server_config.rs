use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, PartialEq)]
pub struct HttpConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
    pub keep_alive: bool,
    // If it's Some, we will manually set the number of threads of HTTP RPC
    // server
    pub threads: Option<usize>,
    pub cors: Option<String>,
}

impl HttpConfiguration {
    pub fn new(
        ip: Option<(u8, u8, u8, u8)>, port: Option<u16>, keep_alive: bool,
        threads: Option<usize>, cors: Option<String>,
    ) -> Self {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        HttpConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
            keep_alive,
            threads,
            cors,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct WsConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
    pub max_payload_bytes: usize,
    pub cors: Option<String>,
}

impl WsConfiguration {
    pub fn new(
        ip: Option<(u8, u8, u8, u8)>, port: Option<u16>,
        max_payload_bytes: usize, cors: Option<String>,
    ) -> Self {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        WsConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
            max_payload_bytes,
            cors,
        }
    }
}
