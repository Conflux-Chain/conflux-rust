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
