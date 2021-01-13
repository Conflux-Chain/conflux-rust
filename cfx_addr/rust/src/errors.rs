// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

use super::consts::AddressType;

use std::{error::Error, fmt};

/// Error concerning encoding of cashaddrs.
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

impl Error for EncodingError {
    fn cause(&self) -> Option<&dyn Error> { None }

    fn description(&self) -> &str { "invalid length" }
}

/// Error concerning decoding of cashaddrs.
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
