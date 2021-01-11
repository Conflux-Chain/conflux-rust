// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

use super::errors::DecodingError;

pub const CHARSET_SIZE: usize = 32;

pub const TYPE_MASK: u8 = 0x78;
// Because we use a different CHARSET than BCH, it's OK that we disregard all of
// the BITCOIN type bits.
//
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

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub enum Network {
    /// Main network.
    Main,
    /// Test network.
    Test,
}

// Prefixes
const MAINNET_PREFIX: &str = "cfx";
const TESTNET_PREFIX: &str = "cfx_test";

impl Network {
    pub fn to_addr_prefix(&self) -> &'static str {
        match self {
            Network::Main => MAINNET_PREFIX,
            Network::Test => TESTNET_PREFIX,
        }
    }

    pub fn from_addr_prefix(prefix: &str) -> Result<Self, DecodingError> {
        match prefix {
            MAINNET_PREFIX => Ok(Network::Main),
            TESTNET_PREFIX => Ok(Network::Test),
            _ => Err(DecodingError::InvalidPrefix(prefix.to_string())),
        }
    }
}
