// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{ABIDecodable, ABIDecodeError, ABIEncodable};
use crate::{ABIPackedEncodable, ABIVariable};
use cfx_types::{Address, U256};
use lazy_static::lazy_static;
use rustc_hex::{FromHex, ToHex};
use solidity_abi_derive::ABIVariable;
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
fn test_static_array() {
    let data: [U256; 2] = [U256::from(17), U256::from(18)];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000011\
         0000000000000000000000000000000000000000000000000000000000000012"
    );
    assert_eq!(<[U256; 2]>::abi_decode(encoded.as_slice()).unwrap(), data);
}

#[test]
fn test_dynamic_array() {
    let data: [String; 2] = ["烤".into(), "仔".into()];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000080\
         0000000000000000000000000000000000000000000000000000000000000003\
         e783a40000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000003\
         e4bb940000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(<[String; 2]>::abi_decode(encoded.as_slice()).unwrap(), data);
}

#[test]
fn test_static_array_in_array() {
    let data: [[U256; 2]; 2] = [
        [U256::from(17), U256::from(18)],
        [U256::from(19), U256::from(20)],
    ];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000011\
         0000000000000000000000000000000000000000000000000000000000000012\
         0000000000000000000000000000000000000000000000000000000000000013\
         0000000000000000000000000000000000000000000000000000000000000014"
    );
    assert_eq!(
        <[[U256; 2]; 2]>::abi_decode(encoded.as_slice()).unwrap(),
        data
    );
}

#[test]
fn test_dynamic_array_in_array() {
    let data: [[String; 2]; 2] = [
        ["a super super super super long string".into(), "cat".into()],
        ["marmota".into(), "donkey".into()],
    ];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000120\
         0000000000000000000000000000000000000000000000000000000000000040\
         00000000000000000000000000000000000000000000000000000000000000a0\
         0000000000000000000000000000000000000000000000000000000000000025\
         61207375706572207375706572207375706572207375706572206c6f6e672073\
         7472696e67000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000003\
         6361740000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000080\
         0000000000000000000000000000000000000000000000000000000000000007\
         6d61726d6f746100000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000006\
         646f6e6b65790000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        <[[String; 2]; 2]>::abi_decode(encoded.as_slice()).unwrap(),
        data
    );
}

#[test]
fn test_array_in_vector() {
    let data: Vec<[U256; 2]> = vec![
        [U256::from(17), U256::from(18)],
        [U256::from(19), U256::from(20)],
    ];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000011\
         0000000000000000000000000000000000000000000000000000000000000012\
         0000000000000000000000000000000000000000000000000000000000000013\
         0000000000000000000000000000000000000000000000000000000000000014"
    );
    assert_eq!(
        <Vec<[U256; 2]>>::abi_decode(encoded.as_slice()).unwrap(),
        data
    );
}

#[test]
fn test_vector_in_array() {
    let data: [Vec<U256>; 2] = [
        vec![U256::from(17), U256::from(18)],
        vec![U256::from(19), U256::from(20)],
    ];
    let encoded = data.abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000040\
         00000000000000000000000000000000000000000000000000000000000000a0\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000011\
         0000000000000000000000000000000000000000000000000000000000000012\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000013\
         0000000000000000000000000000000000000000000000000000000000000014"
    );
    assert_eq!(
        <[Vec<U256>; 2]>::abi_decode(encoded.as_slice()).unwrap(),
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

#[test]
fn test_packed_string() {
    let msg: (Address, Vec<bool>, String) =
        (ADDR1.clone(), vec![false, true, true], "hello".into());
    let encoded = msg.abi_packed_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "176c45928d7c26b0175dec8bf6051108563c62c5\
         000101\
         68656c6c6f"
    );
}

#[derive(ABIVariable, Eq, PartialEq, Debug, Copy, Clone)]
struct StaticStruct {
    user: Address,
    amount: U256,
}

#[test]
fn test_static_struct() {
    let input = StaticStruct {
        user: ADDR1.clone(),
        amount: U256::from(33u64),
    };
    let encoded = input.abi_encode();
    assert_eq!(StaticStruct::BASIC_TYPE, false);
    assert_eq!(StaticStruct::STATIC_LENGTH, Some(64));
    assert_eq!(
        encoded.to_hex::<String>(),
        "000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         0000000000000000000000000000000000000000000000000000000000000021"
    );
    assert_eq!(StaticStruct::abi_decode(encoded.as_slice()).unwrap(), input);
}

#[test]
fn test_static_struct_multi_variable() {
    let input = StaticStruct {
        user: ADDR1.clone(),
        amount: U256::from(33u64),
    };
    let encoded = (3u64, input).abi_encode();
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000003\
         000000000000000000000000176c45928d7c26b0175dec8bf6051108563c62c5\
         0000000000000000000000000000000000000000000000000000000000000021"
    );
    let (out1, out2) =
        <(u64, StaticStruct)>::abi_decode(encoded.as_slice()).unwrap();
    assert_eq!(out1, 3);
    assert_eq!(out2, input);
}

#[derive(ABIVariable, Eq, PartialEq, Debug, Clone)]
struct DynamicStruct {
    id: u64,
    data: Vec<u8>,
}

#[test]
fn test_dynamic_struct() {
    let input = DynamicStruct {
        id: 7,
        data: vec![8, 9],
    };
    let encoded = input.abi_encode();
    assert_eq!(DynamicStruct::STATIC_LENGTH, None);
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000007\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000002\
         0809000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        DynamicStruct::abi_decode(encoded.as_slice()).unwrap(),
        input
    );
}

#[test]
fn test_two_dynamic_struct() {
    let input = vec![
        DynamicStruct {
            id: 33,
            data: vec![5, 6, 7],
        },
        DynamicStruct {
            id: 34,
            data: vec![8, 9],
        },
    ];
    let encoded = input.abi_encode();
    assert_eq!(DynamicStruct::STATIC_LENGTH, None);
    assert_eq!(
        encoded.to_hex::<String>(),
        "0000000000000000000000000000000000000000000000000000000000000020\
         0000000000000000000000000000000000000000000000000000000000000002\
         0000000000000000000000000000000000000000000000000000000000000040\
         00000000000000000000000000000000000000000000000000000000000000c0\
         0000000000000000000000000000000000000000000000000000000000000021\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000003\
         0506070000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000022\
         0000000000000000000000000000000000000000000000000000000000000040\
         0000000000000000000000000000000000000000000000000000000000000002\
         0809000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        Vec::<DynamicStruct>::abi_decode(encoded.as_slice()).unwrap(),
        input
    );
}
