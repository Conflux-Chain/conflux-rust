// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::io::IoError;
use rlp::{self, Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{fmt, io, net};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    DisconnectRequested,
    UselessPeer,
    WrongEndpointInfo,
    IpLimited,
    UpdateNodeIdFailed,
    Blacklisted,
    Custom(String),
    Unknown,
}

impl DisconnectReason {
    fn code(&self) -> u8 {
        match self {
            DisconnectReason::DisconnectRequested => 0,
            DisconnectReason::UselessPeer => 1,
            DisconnectReason::WrongEndpointInfo => 2,
            DisconnectReason::IpLimited => 3,
            DisconnectReason::UpdateNodeIdFailed => 4,
            DisconnectReason::Blacklisted => 5,
            DisconnectReason::Custom(_) => 100,
            DisconnectReason::Unknown => 0xff,
        }
    }
}

impl Encodable for DisconnectReason {
    fn rlp_append(&self, s: &mut RlpStream) {
        let mut raw = vec![self.code()];

        if let DisconnectReason::Custom(msg) = self {
            raw.extend(msg.bytes());
        }

        s.append_raw(&raw[..], raw.len());
    }
}

impl Decodable for DisconnectReason {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        let raw = rlp.as_raw().to_vec();

        if raw.is_empty() {
            return Err(DecoderError::RlpIsTooShort);
        }

        match raw[0] {
            0 => Ok(DisconnectReason::DisconnectRequested),
            1 => Ok(DisconnectReason::UselessPeer),
            2 => Ok(DisconnectReason::WrongEndpointInfo),
            3 => Ok(DisconnectReason::IpLimited),
            4 => Ok(DisconnectReason::UpdateNodeIdFailed),
            5 => Ok(DisconnectReason::Blacklisted),
            100 => match std::str::from_utf8(&raw[1..]) {
                Err(_) => {
                    Err(DecoderError::Custom("Unable to decode message part"))
                }
                Ok(msg) => Ok(DisconnectReason::Custom(msg.to_owned())),
            },
            _ => Ok(DisconnectReason::Unknown),
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
            DisconnectReason::Blacklisted => "blacklisted",
            DisconnectReason::Custom(ref msg) => &msg[..],
            DisconnectReason::Unknown => "unknown",
        };

        f.write_str(msg)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThrottlingReason {
    QueueFull,
    Throttled,
    PacketThrottled(&'static str),
}

impl fmt::Display for ThrottlingReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ThrottlingReason::QueueFull => {
                f.write_str("egress queue capacity reached")
            }
            ThrottlingReason::Throttled => f.write_str("egress throttled"),
            ThrottlingReason::PacketThrottled(name) => {
                let msg = format!("packet {} throttled", name);
                f.write_str(msg.as_str())
            }
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

#[cfg(test)]
mod tests {
    use super::DisconnectReason::{self, *};
    use rlp::{decode, encode};

    fn check_rlp(r: DisconnectReason) {
        assert_eq!(decode::<DisconnectReason>(&encode(&r)).unwrap(), r);
    }

    #[test]
    fn test_disconnect_reason_rlp() {
        check_rlp(DisconnectRequested);
        check_rlp(UselessPeer);
        check_rlp(WrongEndpointInfo);
        check_rlp(IpLimited);
        check_rlp(UpdateNodeIdFailed);
        check_rlp(Unknown);

        check_rlp(Custom("".to_owned()));
        check_rlp(Custom("test test test".to_owned()));
    }
}
