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
    value.write_as_big_endian(&mut buf);
    H256::from(buf)
}

pub fn h256_to_u256_be(value: H256) -> U256 {
    U256::from_big_endian(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use hex;
    #[test]
    fn test_legacy_bool_encode() {
        // by now we need use the legacy bool encoding
        // which is 0x00 for false and 0x01 for true
        // the newer encoding is 0x80 for false and 0x01 for true

        let false_bytes = hex::decode("00").unwrap();
        let true_bytes = hex::decode("01").unwrap();

        assert_eq!(rlp::encode(&false).as_ref(), false_bytes);
        assert_eq!(rlp::encode(&true).as_ref(), true_bytes);

        assert_eq!(rlp::decode::<bool>(&false_bytes), Ok(false));
        assert_eq!(rlp::decode::<bool>(&true_bytes), Ok(true));
    }
}
