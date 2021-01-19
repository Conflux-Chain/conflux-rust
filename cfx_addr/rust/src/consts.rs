// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

use super::errors::{DecodingError, EncodingError, OptionError};

use cfx_types::address_util::{self, AddressUtil};
use std::{fmt, string::ToString};

pub const CHARSET_SIZE: usize = 32;

pub const RESERVED_BITS_MASK: u8 = 0xf8;

// Because we use a different CHARSET than BCH, it's OK that we disregard all of
// the BITCOIN type bits.
//
// // pub const TYPE_MASK: u8 = 0x78;
// // pub const TYPE_BITCOIN_P2PKH: u8 = 0x00;
// // pub const TYPE_BITCOIN_P2SH: u8 = 0x08;
//
// In Conflux we have so far only one type of account key format. So we try to
// use the 4 type bits differently. In the future we may use them in some
// special transaction scenarios. e.g. A payment code, an address linked to
// off-chain or cross-chain mechanism.

pub const SIZE_MASK: u8 = 0x07;
pub const SIZE_160: u8 = 0x00;
// In Conflux we only have 160 bits hash size, however we keep these unused
// sizes for unit test and compatibility.
pub const SIZE_192: u8 = 0x01;
pub const SIZE_224: u8 = 0x02;
pub const SIZE_256: u8 = 0x03;
pub const SIZE_320: u8 = 0x04;
pub const SIZE_384: u8 = 0x05;
pub const SIZE_448: u8 = 0x06;
pub const SIZE_512: u8 = 0x07;

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]
pub enum Network {
    /// Main network.
    Main,
    /// Test network.
    Test,
    /// Specific Network Id.
    Id(u64),
}

// Prefixes
const MAINNET_PREFIX: &str = "cfx";
const TESTNET_PREFIX: &str = "cfxtest";
const NETWORK_ID_PREFIX: &str = "net";
// These two network_ids are reserved.
const RESERVED_NETWORK_IDS: [u64; 2] = [1, 1029];

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AddressType {
    Builtin,
    Contract,
    Null,
    User,
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

impl AddressType {
    const BUILTIN: &'static str = "builtin";
    const CONTRACT: &'static str = "contract";
    const NULL: &'static str = "null";
    const USER: &'static str = "user";

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
            Err(DecodingError::InvalidOption(
                OptionError::InvalidAddressType(text.into()),
            ))
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
            n => Err(EncodingError::InvalidAddressType(n)),
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Builtin => Self::BUILTIN,
            Self::Contract => Self::CONTRACT,
            Self::Null => Self::NULL,
            Self::User => Self::USER,
        }
    }
}

impl ToString for AddressType {
    fn to_string(&self) -> String { self.to_str().into() }
}
