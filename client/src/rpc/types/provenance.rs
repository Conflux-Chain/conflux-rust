// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! Request Provenance

use cfx_types::H256;
use std::{fmt, net::SocketAddr};

/// RPC request origin
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// RPC server (includes request origin)
    Rpc(String),
    /// TCP server (includes peer address)
    Tcp(SocketAddr),
    /// WS server
    Ws {
        /// Session id
        session: H256,
    },
    /// Signer (authorized WS server)
    Signer {
        /// Session id
        session: H256,
    },
    /// From the C API
    CApi,
    /// Unknown
    Unknown,
}

impl Default for Origin {
    fn default() -> Self { Origin::Unknown }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Origin::Rpc(ref origin) => write!(f, "{} via RPC", origin),
            Origin::Tcp(ref address) => write!(f, "TCP (address: {})", address),
            Origin::Ws { ref session } => {
                write!(f, "WebSocket (session: {})", session)
            }
            Origin::Signer { ref session } => {
                write!(f, "Secure Session (session: {})", session)
            }
            Origin::CApi => write!(f, "C API"),
            Origin::Unknown => write!(f, "unknown origin"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfx_types::H256;
    use serde_json;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_origin_serialize() {
        let socket: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let o1 = Origin::default();
        let o2 = Origin::Rpc("test service".into());
        let o3 = Origin::Tcp(socket);
        let o4 = Origin::Signer {
            session: H256::from_low_u64_be(10),
        };
        let o5 = Origin::Unknown;
        let o6 = Origin::Ws {
            session: H256::from_low_u64_be(5),
        };
        let o7 = Origin::CApi;
        let res1 = serde_json::to_string(&o1).unwrap();
        let res2 = serde_json::to_string(&o2).unwrap();
        let res3 = serde_json::to_string(&o3).unwrap();
        let res4 = serde_json::to_string(&o4).unwrap();
        let res5 = serde_json::to_string(&o5).unwrap();
        let res6 = serde_json::to_string(&o6).unwrap();
        let res7 = serde_json::to_string(&o7).unwrap();
        assert_eq!(res1, r#""unknown""#);
        assert_eq!(res2, r#"{"rpc":"test service"}"#);
        assert_eq!(res3, r#"{"tcp":"127.0.0.1:8080"}"#);
        assert_eq!(res4,
        r#"{"signer":{"session":"0x000000000000000000000000000000000000000000000000000000000000000a"}}"#);
        assert_eq!(res5, r#""unknown""#);
        assert_eq!(res6,
        r#"{"ws":{"session":"0x0000000000000000000000000000000000000000000000000000000000000005"}}"#);
        assert_eq!(res7, r#""c-api""#);
    }
    #[test]
    fn test_origin_deserialize() {
        let se1 = r#""unknown""#;
        let se2 = r#"{"rpc":"test service"}"#;
        let se3 = r#"{"tcp":"127.0.0.1:8080"}"#;
        let se4 = r#"{"signer":{"session":"0x000000000000000000000000000000000000000000000000000000000000000a"}}"#;
        let se5 = r#"{"ws":{"session":"0x0000000000000000000000000000000000000000000000000000000000000005"}}"#;
        let se6 = r#""c-api""#;
        let de1: Origin = serde_json::from_str(se1).unwrap();
        let de2: Origin = serde_json::from_str(se2).unwrap();
        let de3: Origin = serde_json::from_str(se3).unwrap();
        let de4: Origin = serde_json::from_str(se4).unwrap();
        let de5: Origin = serde_json::from_str(se5).unwrap();
        let de6: Origin = serde_json::from_str(se6).unwrap();
        let socket: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        assert_eq!(de1, Origin::Unknown);
        assert_eq!(de1, Origin::default());
        assert_eq!(de2, Origin::Rpc("test service".into()));
        assert_eq!(de3, Origin::Tcp(socket));
        assert_eq!(
            de4,
            Origin::Signer {
                session: H256::from_low_u64_be(10),
            }
        );
        assert_eq!(
            de5,
            Origin::Ws {
                session: H256::from_low_u64_be(5),
            }
        );
        assert_eq!(de6, Origin::CApi);
    }
    //    fn should_serialize_origin() {
    //        // given
    //        let o1 = Origin::Rpc("test service".into());
    //        let o3 = Origin::Ipc(H256::from_low_u64_be(5));
    //        let o4 = Origin::Signer {
    //            session: H256::from_low_u64_be(10),
    //        };
    //        let o5 = Origin::Unknown;
    //        let o6 = Origin::Ws {
    //            session: H256::from_low_u64_be(5),
    //        };
    //
    //        // when
    //        let res1 = serde_json::to_string(&o1).unwrap();
    //        let res3 = serde_json::to_string(&o3).unwrap();
    //        let res4 = serde_json::to_string(&o4).unwrap();
    //        let res5 = serde_json::to_string(&o5).unwrap();
    //        let res6 = serde_json::to_string(&o6).unwrap();
    //
    //        // then
    //        assert_eq!(res1, r#"{"rpc":"test service"}"#);
    //        assert_eq!(res3,
    // r#"{"ipc":"
    // 0x0000000000000000000000000000000000000000000000000000000000000005"}"#);
    //        assert_eq!(res4,
    // r#"{"signer":{"session":"
    // 0x000000000000000000000000000000000000000000000000000000000000000a"}}"#);
    //        assert_eq!(res5, r#""unknown""#);
    //        assert_eq!(res6,
    // r#"{"ws":{"session":"
    // 0x0000000000000000000000000000000000000000000000000000000000000005"}}"#);
    //    }
}
