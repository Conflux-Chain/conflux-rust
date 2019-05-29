// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::io::IoError;
use keylib;
use rlp;
use std::{fmt, io, net};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    DisconnectRequested,
    UselessPeer,
    WrongEndpointInfo,
    IpLimited,
    UpdateNodeIdFailed,
    Unknown,
}

impl DisconnectReason {
    pub fn from_u8(n: u8) -> DisconnectReason {
        match n {
            0 => DisconnectReason::DisconnectRequested,
            1 => DisconnectReason::UselessPeer,
            2 => DisconnectReason::WrongEndpointInfo,
            3 => DisconnectReason::IpLimited,
            4 => DisconnectReason::UpdateNodeIdFailed,
            _ => DisconnectReason::Unknown,
        }
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            DisconnectReason::DisconnectRequested => "disconnect requested",
            DisconnectReason::UselessPeer => "useless peer",
            DisconnectReason::WrongEndpointInfo => "wrong node id",
            DisconnectReason::IpLimited => "IP limited",
            DisconnectReason::UpdateNodeIdFailed => "Update node id failed",
            DisconnectReason::Unknown => "unknown",
        };

        f.write_str(msg)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThrottlingReason {
    QueueFull,
    Throttled,
}

impl fmt::Display for ThrottlingReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ThrottlingReason::QueueFull => {
                f.write_str("egress queue capacity reached")
            }
            ThrottlingReason::Throttled => f.write_str("egress throttled"),
        }
    }
}

error_chain! {
    foreign_links {
        SocketIo(IoError);
    }

    errors {
        #[doc = "Error concerning the network address parsing subsystem."]
        AddressParse {
            description("Failed to parse network address"),
            display("Failed to parse network address"),
        }

        #[doc = "Error concerning the network address resolution subsystem."]
        AddressResolve(err: Option<io::Error>) {
            description("Failed to resolve network address"),
            display("Failed to resolve network address {}", err.as_ref().map_or("".to_string(), |e| e.to_string())),
        }

        #[doc = "Authentication failure"]
        Auth {
            description("Authentication failure"),
            display("Authentication failure"),
        }

        BadProtocol {
            description("Bad protocol"),
            display("Bad protocol"),
        }

        BadAddr {
            description("Bad socket address"),
            display("Bad socket address"),
        }

        Decoder {
            description("Decoder error"),
            display("Decoder error"),
        }

        Expired {
            description("Expired message"),
            display("Expired message"),
        }

        Disconnect(reason: DisconnectReason) {
            description("Peer disconnected"),
            display("Peer disconnected: {}", reason),
        }

        #[doc = "Invalid node id"]
        InvalidNodeId {
            description("Invalid node id"),
            display("Invalid node id"),
        }

        OversizedPacket {
            description("Packet is too large"),
            display("Packet is too large"),
        }

        Io(err: io::Error) {
            description("IO Error"),
            display("Unexpected IO error: {}", err),
        }

        Throttling(reason: ThrottlingReason) {
            description("throttling failure"),
            display("throttling failure: {}", reason),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self { Error::from_kind(ErrorKind::Io(err)) }
}

impl From<rlp::DecoderError> for Error {
    fn from(_err: rlp::DecoderError) -> Self { ErrorKind::Decoder.into() }
}

impl From<keylib::Error> for Error {
    fn from(_err: keylib::Error) -> Self { ErrorKind::Auth.into() }
}

impl From<keylib::crypto::Error> for Error {
    fn from(_err: keylib::crypto::Error) -> Self { ErrorKind::Auth.into() }
}

impl From<net::AddrParseError> for Error {
    fn from(_err: net::AddrParseError) -> Self { ErrorKind::BadAddr.into() }
}
