// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

extern crate cfx_types;
#[macro_use]
extern crate lazy_static;
extern crate rustc_hex;

#[allow(dead_code)]
pub mod checksum;
pub mod consts;
pub mod errors;
#[cfg(test)]
mod tests;

use cfx_types::Address;
use checksum::polymod;
pub use consts::{AddressType, Network};
pub use errors::DecodingError;
use errors::*;

const BASE32_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyz";
const EXCLUDE_CHARS: [char; 4] = ['o', 'i', 'l', 'q'];
lazy_static! {
    // Regular expression for application to match string. This regex isn't strict,
    // because our SDK will.
    // "(?i)[:=_-0123456789abcdefghijklmnopqrstuvwxyz]*"
    static ref REGEXP: String = format!{"(?i)[:=_-{}]*", BASE32_CHARS};

    // For encoding.
    static ref CHARSET: Vec<u8> =
        // Remove EXCLUDE_CHARS from charset.
        BASE32_CHARS.replace(&EXCLUDE_CHARS[..], "").into_bytes();

    // For decoding.
    static ref CHAR_INDEX: [Option<u8>; 128] = (|| {
        let mut index = [None; 128];
        assert_eq!(CHARSET.len(), consts::CHARSET_SIZE);
        for i in 0..consts::CHARSET_SIZE {
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

// FIXME: rename to DecodedAddress.
/// Struct containing the bytes and metadata of a Conflux address.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct UserAddress {
    /// Base32 address
    pub base32: String,
    /// Address bytes
    pub bytes: Vec<u8>,
    /// The parsed address in H160 format.
    pub hex: Option<Address>,
    /// Network
    pub network: Network,
}

#[derive(Copy, Clone)]
pub enum EncodingOptions {
    Simple,
    QrCode,
}

// TODO: verbose level and address type.
pub fn cfx_addr_encode(
    raw: &[u8], network: Network, encoding_options: EncodingOptions,
) -> Result<String, EncodingError> {
    // Calculate version byte
    let length = raw.len();
    let version_byte = match length {
        20 => consts::SIZE_160,
        // Conflux does not have other hash sizes. We don't use the sizes below
        // but we kept these for unit tests.
        24 => consts::SIZE_192,
        28 => consts::SIZE_224,
        32 => consts::SIZE_256,
        40 => consts::SIZE_320,
        48 => consts::SIZE_384,
        56 => consts::SIZE_448,
        64 => consts::SIZE_512,
        _ => return Err(EncodingError::InvalidLength(length)),
    };

    // Get prefix
    let prefix = network.to_prefix()?;

    // Convert payload to 5 bit array
    let mut payload = Vec::with_capacity(1 + raw.len());
    payload.push(version_byte);
    payload.extend(raw);
    let payload_5_bits = convert_bits(&payload, 8, 5, true)
        .expect("no error is possible for encoding");

    // Construct payload string using CHARSET
    let payload_str: String = payload_5_bits
        .iter()
        .map(|b| CHARSET[*b as usize] as char)
        .collect();

    // Create checksum
    let expanded_prefix = expand_prefix(&prefix);
    let checksum_input =
        [&expanded_prefix[..], &payload_5_bits, &[0; 8][..]].concat();
    let checksum = polymod(&checksum_input);

    // Convert checksum to string
    let checksum_str: String = (0..8)
        .rev()
        .map(|i| CHARSET[((checksum >> (i * 5)) & 31) as usize] as char)
        .collect();

    // Concatenate all parts
    let cfx_base32_addr = match encoding_options {
        EncodingOptions::Simple => {
            [&prefix, ":", &payload_str, &checksum_str].concat()
        }
        EncodingOptions::QrCode => {
            let addr_type_str = AddressType::from_address(&raw)?.to_str();
            [
                &prefix,
                ":type.",
                addr_type_str,
                ":",
                &payload_str,
                &checksum_str,
            ]
            .concat()
            .to_uppercase()
        }
    };
    Ok(cfx_base32_addr)
}

pub fn cfx_addr_decode(addr_str: &str) -> Result<UserAddress, DecodingError> {
    // FIXME: add a unit test for addr_str in capital letters.
    let has_lowercase = addr_str.chars().any(|c| c.is_lowercase());
    let has_uppercase = addr_str.chars().any(|c| c.is_uppercase());
    if has_lowercase && has_uppercase {
        return Err(DecodingError::MixedCase);
    }
    let lowercase = addr_str.to_lowercase();

    // Delimit and extract prefix
    let parts: Vec<&str> = lowercase.split(':').collect();
    if parts.len() < 2 {
        return Err(DecodingError::NoPrefix);
    }
    let prefix = parts[0];
    // Match network
    let network = Network::from_prefix(prefix)?;

    let mut address_type = None;
    // Parse optional parts. We will ignore everything we can't understand.
    for option_str in &parts[1..parts.len() - 1] {
        let key_value: Vec<&str> = option_str.split('.').collect();
        if key_value.len() != 2 {
            return Err(DecodingError::InvalidOption(OptionError::ParseError(
                (*option_str).into(),
            )));
        }
        // Address type.
        if key_value[0] == "type" {
            address_type = Some(AddressType::parse(key_value[1])?);
        }
    }

    // Do some sanity checks on the payload string
    let payload_str = parts[parts.len() - 1];
    if payload_str.len() == 0 {
        return Err(DecodingError::InvalidLength(0));
    }
    let has_lowercase = payload_str.chars().any(|c| c.is_lowercase());
    let has_uppercase = payload_str.chars().any(|c| c.is_uppercase());
    if has_lowercase && has_uppercase {
        return Err(DecodingError::MixedCase);
    }

    // Decode payload to 5 bit array
    let payload_chars = payload_str.chars();
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
    let payload =
        convert_bits(&payload_5_bits[..(len_5_bit - 8)], 5, 8, false)?;

    // Verify the version byte
    let version = payload[0];

    // Check length
    let body = &payload[1..];
    let body_len = body.len();
    let version_size = version & consts::SIZE_MASK;
    if (version_size == consts::SIZE_160 && body_len != 20)
        // Conflux does not have other hash sizes. We don't use the sizes below
        // but we kept these for unit tests.
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
    // Check reserved bits
    if version & consts::RESERVED_BITS_MASK != 0 {
        return Err(DecodingError::VersionNotRecognized(version));
    }

    let hex_address;
    // Check address type for parsed H160 address.
    if version_size == consts::SIZE_160 {
        hex_address = Some(Address::from_slice(body));
        match address_type {
            Some(expected) => {
                let got =
                    AddressType::from_address(hex_address.as_ref().unwrap())
                        .or(Err(()));
                if got.as_ref() != Ok(&expected) {
                    return Err(DecodingError::InvalidOption(
                        OptionError::AddressTypeMismatch { expected, got },
                    ));
                }
            }
            None => {}
        }
    } else {
        hex_address = None;
    }

    Ok(UserAddress {
        base32: addr_str.to_lowercase(),
        bytes: body.to_vec(),
        hex: hex_address,
        network,
    })
}

/// The checksum calculation includes the lower 5 bits of each character of the
/// prefix.
/// - e.g. "bit..." becomes 2,9,20,...
// Expand the address prefix for the checksum operation.
fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = prefix.chars().map(|c| (c as u8) & 0x1f).collect();
    ret.push(0);
    ret
}

// This method assume that data is valid string of inbits.
// When pad is true, any remaining bits are padded and encoded into a new byte;
// when pad is false, any remaining bits are checked to be zero and discarded.
fn convert_bits(
    data: &[u8], inbits: u8, outbits: u8, pad: bool,
) -> Result<Vec<u8>, DecodingError> {
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
        while num >= outbits {
            // Store only the highest outbits.
            ret.push((acc >> (num - outbits)) as u8);
            // Clear the highest outbits.
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
        // FIXME: add unit tests for it.
        // If there's some bits left, figure out if we need to remove padding
        // and add it
        let padding = ((data.len() * inbits as usize) % outbits as usize) as u8;
        if num >= inbits || acc != 0 {
            return Err(DecodingError::InvalidPadding {
                from_bits: inbits,
                padding_bits: padding,
                padding: acc,
            });
        }
    }
    Ok(ret)
}
