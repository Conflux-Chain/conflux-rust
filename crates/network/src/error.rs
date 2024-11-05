// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{io::IoError, service::ProtocolVersion, ProtocolId};
use rlp::{self, Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{fmt, io, net};
use thiserror::Error;

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


#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    SocketIo(#[from] IoError),
    ///Error concerning the network address parsing subsystem.
    #[error("Failed to parse network address")]
    AddressParse,
    ///Error concerning the network address resolution subsystem.
    #[error("Failed to resolve network address {}", .0.as_ref().map_or("".to_string(), |e| e.to_string()))]
    AddressResolve(Option<io::Error>),
    /// Authentication failure
    #[error("Authentication failure")]
    Auth,
    #[error("Bad protocol")]
    BadProtocol,
    #[error("Bad socket address")]
    BadAddr,
    #[error("Decoder error: reason={0}")]
    Decoder(String),
    #[error("Expired message")]
    Expired,
    #[error("Peer disconnected: {0}")]
    Disconnect(String),
    ///Invalid node id
    #[error("Invalid node id")]
    InvalidNodeId,
    #[error("Packet is too large")]
    OversizedPacket,
    #[error("Unexpected IO error: {0}")]
    Io(io::Error),
    #[error("Received message is deprecated. Protocol {protocol:?}, message id {msg_id}, \
                min_supported_version {min_supported_version}")]
    MessageDeprecated {
        protocol: ProtocolId,
        msg_id: u16,
        min_supported_version: ProtocolVersion,
    },
    #[error("We are trying to send unsupported message to peer. Protocol {protocol:?},\
                message id {msg_id}, peer_protocol_version {peer_protocol_version:?}, min_supported_version {min_supported_version:?}")]
    SendUnsupportedMessage {
        protocol: ProtocolId,
        msg_id: u16,
        peer_protocol_version: Option<ProtocolVersion>,
        min_supported_version: Option<ProtocolVersion>,
    },
    #[error("throttling failure: {0}")]
    Throttling(ThrottlingReason),

    #[error("{0}")]
    Msg(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self { Error::from(Error::Io(err)) }
}

impl From<rlp::DecoderError> for Error {
    fn from(err: rlp::DecoderError) -> Self {
        Error::Decoder(format!("{}", err)).into()
    }
}

impl From<keylib::Error> for Error {
    fn from(_err: keylib::Error) -> Self { Error::Auth.into() }
}

impl From<keylib::crypto::Error> for Error {
    fn from(_err: keylib::crypto::Error) -> Self { Error::Auth.into() }
}

impl From<net::AddrParseError> for Error {
    fn from(_err: net::AddrParseError) -> Self { Error::BadAddr.into() }
}
impl From<&str> for Error {
    fn from(s: &str) -> Error { Error::Msg(s.into()) }
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
