// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

use crate::consts::{
    ADDRESS_TYPE_BUILTIN, ADDRESS_TYPE_CONTRACT, ADDRESS_TYPE_NULL,
    ADDRESS_TYPE_UNKNOWN, ADDRESS_TYPE_USER, MAINNET_PREFIX, NETWORK_ID_PREFIX,
    RESERVED_NETWORK_IDS, TESTNET_PREFIX,
};
use cfx_types::{
    address_util::{self, AddressUtil},
    Address,
};
use core::fmt;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

/// Struct containing the raw bytes and metadata of a Conflux address.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct DecodedRawAddress {
    /// Base32 address. This is included for debugging purposes.
    pub input_base32_address: String,
    /// Address bytes
    pub parsed_address_bytes: Vec<u8>,
    /// The parsed address in H160 format.
    pub hex_address: Option<Address>,
    /// Network
    pub network: Network,
}

#[derive(Copy, Clone)]
pub enum EncodingOptions {
    Simple,
    QrCode,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub enum Network {
    /// Main network.
    Main,
    /// Test network.
    Test,
    /// Specific Network Id.
    Id(u64),
}

impl Network {
    pub fn to_prefix(&self) -> Result<String, EncodingError> {
        match self {
            Network::Main => Ok(MAINNET_PREFIX.into()),
            Network::Test => Ok(TESTNET_PREFIX.into()),
            Network::Id(network_id) => {
                if RESERVED_NETWORK_IDS.contains(network_id) {
                    Err(EncodingError::InvalidNetworkId(*network_id))
                } else {
                    Ok(format!("net{}", network_id))
                }
            }
        }
    }

    pub fn from_prefix(prefix: &str) -> Result<Self, DecodingError> {
        match prefix {
            MAINNET_PREFIX => Ok(Network::Main),
            TESTNET_PREFIX => Ok(Network::Test),
            _ => {
                let maybe_network_id = if !prefix.starts_with(NETWORK_ID_PREFIX)
                {
                    None
                } else {
                    match prefix[NETWORK_ID_PREFIX.len()..].parse::<u64>() {
                        Err(_) => None,
                        Ok(network_id) => {
                            // Check if network_id is valid.
                            if RESERVED_NETWORK_IDS.contains(&network_id) {
                                None
                            } else {
                                Some(network_id)
                            }
                        }
                    }
                };

                match maybe_network_id {
                    None => {
                        Err(DecodingError::InvalidPrefix(prefix.to_string()))
                    }
                    Some(network_id) => Ok(Network::Id(network_id)),
                }
            }
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_prefix() {
            Err(EncodingError::InvalidNetworkId(network_id)) => {
                write!(f, "invalid network prefix net{}", network_id)
            }
            Err(_) => unreachable!(),
            Ok(prefix) => write!(f, "{}", prefix),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressType {
    Builtin,
    Contract,
    Null,
    User,
    Unknown,
}

impl AddressType {
    const BUILTIN: &'static str = ADDRESS_TYPE_BUILTIN;
    const CONTRACT: &'static str = ADDRESS_TYPE_CONTRACT;
    const NULL: &'static str = ADDRESS_TYPE_NULL;
    const UNKNOWN: &'static str = ADDRESS_TYPE_UNKNOWN;
    const USER: &'static str = ADDRESS_TYPE_USER;

    pub fn parse(text: &str) -> Result<Self, DecodingError> {
        if text == Self::BUILTIN {
            Ok(Self::Builtin)
        } else if text == Self::CONTRACT {
            Ok(Self::Contract)
        } else if text == Self::NULL {
            Ok(Self::Null)
        } else if text == Self::USER {
            Ok(Self::User)
        } else {
            Ok(Self::Unknown)
        }
    }

    pub fn from_address<T: AddressUtil>(
        address_hex: &T,
    ) -> Result<Self, EncodingError> {
        match address_hex.address_type_bits() {
            address_util::TYPE_BITS_BUILTIN => {
                if address_hex.is_null_address() {
                    Ok(Self::Null)
                } else {
                    Ok(Self::Builtin)
                }
            }
            address_util::TYPE_BITS_CONTRACT => Ok(Self::Contract),
            address_util::TYPE_BITS_USER_ACCOUNT => Ok(Self::User),
            _ => Ok(Self::Unknown),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Builtin => Self::BUILTIN,
            Self::Contract => Self::CONTRACT,
            Self::Null => Self::NULL,
            Self::User => Self::USER,
            Self::Unknown => Self::UNKNOWN,
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Error concerning encoding of cfx_base32_addr.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EncodingError {
    InvalidAddressType(u8),
    InvalidLength(usize),
    InvalidNetworkId(u64),
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidAddressType(type_byte) => {
                write!(f, "unrecognized type bits 0x{:02x}", type_byte)
            }
            Self::InvalidLength(length) => {
                write!(f, "invalid length ({})", length)
            }
            Self::InvalidNetworkId(network_id) => {
                write!(f, "invalid network_id (reserved: {})", network_id)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for EncodingError {
    fn cause(&self) -> Option<&dyn Error> { None }

    fn description(&self) -> &str { "invalid length" }
}

/// Error concerning decoding of cfx_base32_addr.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodingError {
    /// Invalid length (length).
    InvalidLength(usize),
    /// Zero or multiple prefixes.
    NoPrefix,
    /// Failed to match known prefixes (prefix).
    InvalidPrefix(String),
    /// Failed to match known options.
    InvalidOption(OptionError),
    /// Checksum failed (checksum).
    ChecksumFailed(u64),
    /// Unexpected character (char).
    InvalidChar(char),
    /// Padding is invalid. Either padding_bits > from_bits or
    /// padding is non-zero.
    InvalidPadding {
        from_bits: u8,
        padding_bits: u8,
        padding: u16,
    },
    /// Version byte was not recognized.
    VersionNotRecognized(u8),
    /// Upper and lowercase address string.
    MixedCase,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OptionError {
    /// The option string isn't in a valid format.
    ParseError(String),
    /// The address type specified in option doesn't match the decoded address.
    /// The got can be an Err(()) because decoded address may have invalid
    /// address type.
    AddressTypeMismatch {
        expected: AddressType,
        got: Result<AddressType, ()>,
    },
    /// The address type is invalid.
    InvalidAddressType(String),
}

impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodingError::ChecksumFailed(actual) => {
                write!(f, "invalid checksum (actual {} != 0)", actual)
            }
            DecodingError::InvalidChar(index) => {
                write!(f, "invalid char ({})", index)
            }
            DecodingError::InvalidLength(length) => {
                write!(f, "invalid length ({})", length)
            }
            DecodingError::InvalidPadding {
                from_bits,
                padding_bits,
                padding,
            } => {
                write!(f, "invalid padding (")?;
                if padding_bits >= from_bits {
                    write!(
                        f,
                        "padding_bits({}) >= from_bits({})",
                        padding_bits, from_bits
                    )?;
                    if *padding != 0 {
                        write!(f, ", padding({:#b}) is non-zero)", padding)?;
                    }
                } else {
                    write!(f, "padding({:#b}) is non-zero)", padding)?;
                }
                Ok(())
            }
            DecodingError::InvalidPrefix(prefix) => {
                write!(f, "invalid prefix ({})", prefix)
            }
            DecodingError::InvalidOption(option_error) => match option_error {
                OptionError::AddressTypeMismatch { expected, got } => {
                    write!(f, "expected address type specified in option {:?}, decoded address type {:?}", expected, got)
                }
                OptionError::ParseError(option_str) => {
                    write!(f, "invalid option string ({})", option_str)
                }
                OptionError::InvalidAddressType(type_str) => {
                    write!(f, "invalid address type ({})", type_str)
                }
            },
            DecodingError::NoPrefix => write!(f, "zero or multiple prefixes"),
            DecodingError::MixedCase => write!(f, "mixed case string"),
            DecodingError::VersionNotRecognized(c) => {
                write!(f, "version byte ({}) not recognized", c)
            }
        }
    }
}

#[cfg(feature = "std")]
impl Error for DecodingError {
    fn cause(&self) -> Option<&dyn Error> { None }

    fn description(&self) -> &str {
        match self {
            DecodingError::ChecksumFailed { .. } => "invalid checksum",
            DecodingError::InvalidChar(_) => "invalid char",
            DecodingError::InvalidLength(_) => "invalid length",
            DecodingError::InvalidOption(option_error) => match option_error {
                OptionError::AddressTypeMismatch { .. } => {
                    "decoded address does not match address type in option"
                }
                OptionError::ParseError(_) => "invalid option",
                OptionError::InvalidAddressType(_) => "invalid address type",
            },
            DecodingError::InvalidPadding { .. } => "invalid padding",
            DecodingError::InvalidPrefix(_) => "invalid prefix",
            DecodingError::NoPrefix => "zero or multiple prefixes",
            DecodingError::MixedCase => "mixed case string",
            DecodingError::VersionNotRecognized(_) => {
                "version byte not recognized"
            }
        }
    }
}
