use ethereum_types::{Address, H256, U256};
use std::str::FromStr;

pub fn maybe_address(address: &Address) -> Option<Address> {
    if address.is_zero() {
        None
    } else {
        Some(*address)
    }
}

pub fn hexstr_to_h256(hex_str: &str) -> H256 {
    assert_eq!(hex_str.len(), 64);
    let mut bytes: [u8; 32] = Default::default();

    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
    }

    H256::from(bytes)
}

pub fn option_vec_to_hex(data: Option<&Vec<u8>>) -> String {
    match data {
        Some(vec) => {
            format!("0x{}", hex::encode(vec))
        }
        None => String::from("None"),
    }
}

pub fn parse_hex_string<F: FromStr>(hex_str: &str) -> Result<F, F::Err> {
    hex_str.strip_prefix("0x").unwrap_or(hex_str).parse()
}

pub fn u256_to_h256_be(value: U256) -> H256 {
    let mut buf = [0u8; 32];
    value.to_big_endian(&mut buf);
    H256::from(buf)
}

pub fn h256_to_u256_be(value: H256) -> U256 {
    U256::from_big_endian(value.as_bytes())
}

/// Creates an Ethereum address from an EVM word's upper 20 bytes
pub fn u256_to_address_be(value: U256) -> Address {
    let mut buf = [0u8; 32];
    value.to_big_endian(&mut buf);
    let mut addr_bytes: [u8; 20] = [0u8; 20];
    addr_bytes.copy_from_slice(&buf[12..]);
    Address::from(addr_bytes)
}
