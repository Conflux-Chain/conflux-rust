// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

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

pub const BASE32_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
pub const EXCLUDE_CHARS: [char; 4] = ['o', 'i', 'l', 'q'];

// network prefix
pub const MAINNET_PREFIX: &str = "cfx";
pub const TESTNET_PREFIX: &str = "cfxtest";
pub const NETWORK_ID_PREFIX: &str = "net";

// address types
pub const ADDRESS_TYPE_BUILTIN: &'static str = "builtin";
pub const ADDRESS_TYPE_CONTRACT: &'static str = "contract";
pub const ADDRESS_TYPE_NULL: &'static str = "null";
pub const ADDRESS_TYPE_UNKNOWN: &'static str = "unknown";
pub const ADDRESS_TYPE_USER: &'static str = "user";

// These two network_ids are reserved.
pub const RESERVED_NETWORK_IDS: [u64; 2] = [1, 1029];

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};
use lazy_static::lazy_static;

lazy_static! {
    // Regular expression for application to match string. This regex isn't strict,
    // because our SDK will.
    // "(?i)[:=_-0123456789abcdefghijklmnopqrstuvwxyz]*"
    pub static ref REGEXP: String = format!{"(?i)[:=_-{}]*", BASE32_CHARS};

    // For encoding.
    pub static ref CHARSET: Vec<u8> =
        // Remove EXCLUDE_CHARS from charset.
        BASE32_CHARS.replace(&EXCLUDE_CHARS[..], "").into_bytes();

    // For decoding.
    pub static ref CHAR_INDEX: [Option<u8>; 128] = (|| {
        let mut index = [None; 128];
        assert_eq!(CHARSET.len(), CHARSET_SIZE);
        for i in 0..CHARSET_SIZE {
            let c = CHARSET[i] as usize;
            index[c] = Some(i as u8);
            // Support uppercase as well.
            let u = (c as u8 as char).to_ascii_uppercase() as u8 as usize;
            if u != c {
                index[u] = Some(i as u8);
            }
        }
        return index;
    }) ();
}
