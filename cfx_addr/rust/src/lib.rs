// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

#[macro_use]
extern crate lazy_static;
extern crate rustc_hex;

#[allow(dead_code)]
pub mod checksum;
pub mod consts;
pub mod errors;
#[cfg(test)]
mod tests;

use checksum::polymod;
use consts::Network;
use errors::*;

const EXCLUDE_CHARS: [char; 4] = ['o', 'i', 'l', 'q'];
lazy_static! {
    // For encoding.
    static ref CHARSET: Vec<u8> =
        // Remove EXCLUDE_CHARS from charset.
        "0123456789abcdefghijklmnopqrstuvwxyz".replace(&EXCLUDE_CHARS[..], "").into_bytes();

    // For decoding.
    static ref CHAR_INDEX: [Option<u8>; 128] = (|| {
        let mut index = [None; 128];
        assert_eq!(CHARSET.len(), consts::CHARSET_SIZE);
        for i in 0..consts::CHARSET_SIZE {
            let c = CHARSET[i] as usize;
            index[c] = Some(i as u8);
        }
        return index;
    }) ();
}

/// Struct containing the bytes and metadata of a Conflux address.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct UserAddress {
    /// Address bytes
    pub body: Vec<u8>,
    /// Network
    pub network: Network,
}

pub fn cfx_addr_encode(
    raw: &[u8], network: Network,
) -> Result<String, EncodingError> {
    // Calculate version byte
    let is_testnet_flag = match network {
        Network::Test => consts::TYPE_CFX_TESTNET_FLAG,
        Network::Main => 0,
    };
    let length = raw.len();
    let version_byte = match length {
        20 => consts::SIZE_160,
        24 => consts::SIZE_192,
        28 => consts::SIZE_224,
        32 => consts::SIZE_256,
        40 => consts::SIZE_320,
        48 => consts::SIZE_384,
        56 => consts::SIZE_448,
        64 => consts::SIZE_512,
        _ => return Err(EncodingError::InvalidLength(length)),
    } | is_testnet_flag;

    // Get prefix
    let prefix = network.to_addr_prefix();

    // Convert payload to 5 bit array
    let mut payload = Vec::with_capacity(1 + raw.len());
    payload.push(version_byte);
    payload.extend(raw);
    let payload_5_bits = convert_bits(&payload, 8, 5, true);

    // Construct payload string using CHARSET
    let payload_str: String = payload_5_bits
        .iter()
        .map(|b| CHARSET[*b as usize] as char)
        .collect();

    // Create checksum
    let expanded_prefix = expand_prefix(prefix);
    let checksum_input =
        [&expanded_prefix[..], &payload_5_bits, &[0; 8][..]].concat();
    let checksum = polymod(&checksum_input);

    // Convert checksum to string
    let checksum_str: String = (0..8)
        .rev()
        .map(|i| CHARSET[((checksum >> (i * 5)) & 31) as usize] as char)
        .collect();

    // Concatentate all parts
    let cashaddr = [prefix, ":", &payload_str, &checksum_str].concat();
    Ok(cashaddr)
}

pub fn cfx_addr_decode(addr_str: &str) -> Result<UserAddress, DecodingError> {
    // Delimit and extract prefix
    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() != 2 {
        return Err(DecodingError::NoPrefix);
    }
    let prefix = parts[0];
    let payload_str = parts[1];

    // Match network
    let network = Network::from_addr_prefix(prefix)?;

    // Do some sanity checks on the string
    if payload_str.len() == 0 {
        return Err(DecodingError::InvalidLength(0));
    }

    let has_lowercase = payload_str.chars().any(|c| c.is_lowercase());
    let has_uppercase = payload_str.chars().any(|c| c.is_uppercase());
    if has_lowercase && has_uppercase {
        return Err(DecodingError::MixedCase);
    }

    // Decode payload to 5 bit array
    let payload_chars = payload_str.chars(); // Reintialize iterator here
    let payload_5_bits: Result<Vec<u8>, DecodingError> = payload_chars
        .map(|c| {
            let i = c as usize;
            if let Some(Some(d)) = CHAR_INDEX.get(i) {
                Ok(*d as u8)
            } else {
                Err(DecodingError::InvalidChar(c))
            }
        })
        .collect();
    let payload_5_bits = payload_5_bits?;

    // Verify the checksum
    let checksum =
        polymod(&[&expand_prefix(prefix), &payload_5_bits[..]].concat());
    if checksum != 0 {
        // TODO: according to the spec it is possible to do correction based on
        // the checksum,  we shouldn't do it automatically but we could
        // include the corrected address in  the error.
        return Err(DecodingError::ChecksumFailed(checksum));
    }

    // Convert from 5 bit array to byte array
    let len_5_bit = payload_5_bits.len();
    let payload = convert_bits(&payload_5_bits[..(len_5_bit - 8)], 5, 8, false);

    // Verify the version byte
    let version = payload[0];

    // Check length
    let body = &payload[1..];
    let body_len = body.len();
    let version_size = version & consts::SIZE_MASK;
    if (version_size == consts::SIZE_160 && body_len != 20)
        || (version_size == consts::SIZE_192 && body_len != 24)
        || (version_size == consts::SIZE_224 && body_len != 28)
        || (version_size == consts::SIZE_256 && body_len != 32)
        || (version_size == consts::SIZE_320 && body_len != 40)
        || (version_size == consts::SIZE_384 && body_len != 48)
        || (version_size == consts::SIZE_448 && body_len != 56)
        || (version_size == consts::SIZE_512 && body_len != 64)
    {
        return Err(DecodingError::InvalidLength(body_len));
    }

    // Extract the is_testnet_flag type and return
    let version_type = version & consts::TYPE_MASK;
    let is_testnet_flag = version_type & consts::TYPE_CFX_TESTNET_FLAG;
    if !match network {
        Network::Main => is_testnet_flag == 0,
        Network::Test => is_testnet_flag != 0,
    } {
        return Err(DecodingError::InvalidVersion(version));
    };

    Ok(UserAddress {
        body: body.to_vec(),
        network,
    })
}

// FIXME: I haven't examined this code.
// Expand the address prefix for the checksum operation.
fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = prefix.chars().map(|c| (c as u8) & 0x1f).collect();
    ret.push(0);
    ret
}

// FIXME: I haven't examined this code.
fn convert_bits(data: &[u8], inbits: u8, outbits: u8, pad: bool) -> Vec<u8> {
    assert!(inbits <= 8 && outbits <= 8);
    let num_bytes = (data.len() * inbits as usize + outbits as usize - 1)
        / outbits as usize;
    let mut ret = Vec::with_capacity(num_bytes);
    let mut acc: u16 = 0; // accumulator of bits
    let mut num: u8 = 0; // num bits in acc
    let groupmask = (1 << outbits) - 1;
    for d in data.iter() {
        // We push each input chunk into a 16-bit accumulator
        acc = (acc << inbits) | u16::from(*d);
        num += inbits;
        // Then we extract all the output groups we can
        while num > outbits {
            ret.push((acc >> (num - outbits)) as u8);
            acc &= !(groupmask << (num - outbits));
            num -= outbits;
        }
    }
    if pad {
        // If there's some bits left, pad and add it
        if num > 0 {
            ret.push((acc << (outbits - num)) as u8);
        }
    } else {
        // If there's some bits left, figure out if we need to remove padding
        // and add it
        let padding = (data.len() * inbits as usize) % outbits as usize;
        if num as usize > padding {
            ret.push((acc >> padding) as u8);
        }
    }
    ret
}
