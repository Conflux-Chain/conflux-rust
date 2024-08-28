use ethereum_types::{Address, H256};
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
