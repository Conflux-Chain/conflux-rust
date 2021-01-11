// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{ABIDecodable, ABIDecodeError, ABIEncodable};
use cfx_types::{Address, U256};
use lazy_static;
use rustc_hex::{FromHex, ToHex};
use std::str::FromStr;

lazy_static! {
    static ref ADDR1: Address =
        Address::from_str("176c45928d7c26b0175dec8bf6051108563c62c5").unwrap();
    static ref ADDR2: Address =
        Address::from_str("19c742cec42b9e4eff3b84cdedcde2f58a36f44f").unwrap();
}

#[test]
fn test_address() {
    let addr: Address = ADDR1.clone();
    let mut encoded = addr.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5"
    );
    assert_eq!(Address::abi_decode(encoded.as_slice()).unwrap(), addr);

    // The Solidity ABIEncoder V1 ignores padding zeros.
    encoded[0] = 12;
    assert_eq!(Address::abi_decode(encoded.as_slice()).unwrap(), addr);

    // The Solidity ABIEncoder V1 also ignores additional data.
    encoded.push(12);
    assert_eq!(Address::abi_decode(encoded.as_slice()).unwrap(), addr);

    encoded.pop();
    encoded.pop();

    assert_eq!(
        Address::abi_decode(encoded.as_slice()).unwrap_err(),
        ABIDecodeError("Incomplete static input parameter")
    );
}

#[test]
fn test_u256() {
    let integer: U256 = U256::from(33);
    let mut encoded = integer.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000021"
    );
    assert_eq!(U256::abi_decode(encoded.as_slice()).unwrap(), integer);

    encoded.push(12);
    assert_eq!(U256::abi_decode(encoded.as_slice()).unwrap(), integer);

    encoded.pop();
    encoded.pop();

    assert_eq!(
        Address::abi_decode(encoded.as_slice()).unwrap_err(),
        ABIDecodeError("Incomplete static input parameter")
    );
}

#[test]
fn test_bool() {
    assert_eq!(
        true.abi_encode().to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        false.abi_encode().to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    // The Solidity ABIEncoder V1 ignores padding zeros.
    assert!(bool::abi_decode(U256::from(33).abi_encode().as_slice()).unwrap());
}

#[test]
fn test_static_tuple() {
    let addr: Address = ADDR1.clone();
    let amt: U256 = U256::from(33);
    let encoded = (addr, amt).abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         0000000000000000000000000000000000000000000000000000000000000021"
    );
    assert_eq!(
        <(Address, U256)>::abi_decode(encoded.as_slice()).unwrap(),
        (addr, amt)
    );
}

#[test]
fn test_vector() {
    let addresses: Vec<Address> = vec![ADDR1.clone(), ADDR2.clone()];
    let encoded = addresses.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000002\
         000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         00000000000000000000000019c742cec42b9e4eff3b84cdedcde2f58a36f44f"
    );
    assert_eq!(
        <Vec<Address>>::abi_decode(encoded.as_slice()).unwrap(),
        addresses
    );
}

#[test]
fn test_vector_in_tuple() {
    let addresses: Vec<Address> = vec![ADDR1.clone(), ADDR2.clone()];
    let amt: U256 = U256::from(33);
    let encoded = (amt, addresses.clone()).abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000021\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000002\
         000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         00000000000000000000000019c742cec42b9e4eff3b84cdedcde2f58a36f44f"
    );
    assert_eq!(
        <(U256, Vec<Address>)>::abi_decode(encoded.as_slice()).unwrap(),
        (amt, addresses.clone())
    );

    let encoded = (addresses.clone(), amt).abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000021\
         0000000000000000000000000000000000000000000000000000000000000002\
         000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         00000000000000000000000019c742cec42b9e4eff3b84cdedcde2f58a36f44f"
    );
    assert_eq!(
        <(Vec<Address>, U256)>::abi_decode(encoded.as_slice()).unwrap(),
        (addresses, amt)
    );
}

#[test]
fn test_vector_in_vector() {
    let data: Vec<Vec<U256>> = vec![
        vec![U256::from(17), U256::from(18)],
        vec![U256::from(19), U256::from(20), U256::from(21)],
    ];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000040\
         00000000000000000000000000000000000000000000000000000000000000a0\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000011\
         0000000000000000000000000000000000000000000000000000000000000012\
         0000000000000000000000000000000000000000000000000000000000000003\
         0000000000000000000000000000000000000000000000000000000000000013\
         0000000000000000000000000000000000000000000000000000000000000014\
         0000000000000000000000000000000000000000000000000000000000000015"
    );
    assert_eq!(
        <Vec<Vec<U256>>>::abi_decode(encoded.as_slice()).unwrap(),
        data
    );
}

#[test]
fn test_strange_input() {
    // The following input is strange. It contains two input parameters.
    // The data of the first parameter is in the 3-rd line to the 5-th line.
    // The data of the second parameter is in the 5-th line to the 7-th line.
    // However, the solidity with ABIEncoder V1 ignores such overlap.
    let input_hex =
        "0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000080\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000001\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000003\
         0000000000000000000000000000000000000000000000000000000000000004";
    let encoded = input_hex.from_hex::<Vec<u8>>().unwrap();
    let output = (
        vec![U256::from(1), U256::from(2)],
        vec![U256::from(3), U256::from(4)],
    );
    assert_eq!(
        <(Vec<U256>, Vec<U256>)>::abi_decode(encoded.as_slice()).unwrap(),
        output
    );
}

#[test]
fn test_string() {
    let msg: String = "abi test".to_string();
    let encoded = msg.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000008\
         6162692074657374000000000000000000000000000000000000000000000000"
    );
    assert_eq!(String::abi_decode(encoded.as_slice()).unwrap(), msg);
}

#[test]
fn test_string_utf8() {
    let msg: String = "中文测试".to_string();
    let encoded = msg.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         000000000000000000000000000000000000000000000000000000000000000c\
         e4b8ade69687e6b58be8af950000000000000000000000000000000000000000"
    );
    assert_eq!(String::abi_decode(encoded.as_slice()).unwrap(), msg);
}

#[test]
fn test_long_string() {
    let msg: String = "0123456789abcdef0123456789abcdef".to_string();
    let encoded = msg.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000020\
         3031323334353637383961626364656630313233343536373839616263646566"
    );
    assert_eq!(String::abi_decode(encoded.as_slice()).unwrap(), msg);

    let msg: String = "0123456789abcdef0123456789abcdef0".to_string();
    let encoded = msg.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000021\
         3031323334353637383961626364656630313233343536373839616263646566\
         3000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(String::abi_decode(encoded.as_slice()).unwrap(), msg);
}
