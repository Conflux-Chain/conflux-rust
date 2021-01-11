// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

use std::{error::Error, fmt};

/// Error concerning encoding of cashaddrs.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EncodingError {
    InvalidLength(usize),
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength(length) => {
                write!(f, "invalid length ({})", length)
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
    /// Checksum failed (checksum).
    ChecksumFailed(u64),
    /// Unexpected character (char).
    InvalidChar(char),
    /// Version byte was not recognized.
    InvalidVersion(u8),
    /// Upper and lowercase address string.
    MixedCase,
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
            DecodingError::NoPrefix => write!(f, "zero or multiple prefixes"),
            DecodingError::MixedCase => write!(f, "mixed case string"),
            DecodingError::InvalidVersion(c) => {
                write!(f, "invalid version byte ({})", c)
            }
            DecodingError::InvalidPrefix(prefix) => {
                write!(f, "invalid prefix ({})", prefix)
            }
            DecodingError::InvalidLength(length) => {
                write!(f, "invalid length ({})", length)
            }
        }
    }
}

impl Error for DecodingError {
    fn cause(&self) -> Option<&dyn Error> { None }

    fn description(&self) -> &str {
        match *self {
            DecodingError::ChecksumFailed { .. } => "invalid checksum",
            DecodingError::InvalidChar(_) => "invalid char",
            DecodingError::NoPrefix => "zero or multiple prefixes",
            DecodingError::MixedCase => "mixed case string",
            DecodingError::InvalidVersion(_) => "invalid version byte",
            DecodingError::InvalidPrefix(_) => "invalid prefix",
            DecodingError::InvalidLength(_) => "invalid length",
        }
    }
}
