// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-cfx-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-cfx-addr.

use super::{consts::Network, *};
use rustc_hex::FromHex;

#[test]
fn mainnet_20byte() {
    // 20-byte public key hash on mainnet
    verify(
        Network::Main,
        &"F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
            .from_hex()
            .unwrap(),
        "cfx:03uvyj5kjzdee2z85cycmhwkz3njpv6ut404kg24d3",
    );
}

#[test]
fn mainnet_24byte() {
    // 24-byte public key hash on mainnet
    verify(
        Network::Main,
        &"7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
            .from_hex()
            .unwrap(),
        "cfx:05xdrxp1e22bt1p1e1m2fd0uavuwmcm6b4jyjhrah5yarrsk",
    );
}

#[test]
fn mainnet_28byte() {
    // 28-byte public key hash on mainnet
    verify(
        Network::Main,
        &"3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
            .from_hex()
            .unwrap(),
        "cfx:08x89yefa6nek2hvpeksrwbac61rj2sse68jccjvzg60epsfkmp7pfx",
    );
}

#[test]
fn mainnet_32byte() {
    // 32-byte public key hash on mainnet
    verify(
        Network::Main,
        &"3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
            .from_hex()
            .unwrap(),
        "cfx:0csr7vv64f3b93zx38yws36692dgm1xv8yhryhyfxx7yd7f84r060ts1bh7b2",
    );
}

#[test]
fn mainnet_40byte() {
    // 40-byte public key hash on mainnet
    verify(
        Network::Main,
        &"C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB".from_hex().unwrap(),
        "cfx:0k072e1j7s0fmky14b9vgpwp53n822tz70bgce2y52dgp9b326bx355ns8wbxc9pzc6wyh3134",
    );
}

#[test]
fn mainnet_48byte() {
    // 48-byte public key hash on mainnet
    verify(
        Network::Main,
        &"E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C".from_hex().unwrap(),
        "cfx:0rhp3jmufych0z0rmshe0hz3ehekw6efg17dcf2w833bmxhpjuws4g927p6ecapmhp33yk5hhj9gwk0p7j3465g",
    );
}

#[test]
fn mainnet_56byte() {
    // 56-byte public key hash on mainnet
    verify(
        Network::Main,
        &"D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041".from_hex().unwrap(),
        "cfx:0vczmz2cdvupvh7z88xuntpmjrdzythx0d575mewfn9crzkx3tm5hyen4ep0myjw6g3rce74vmd706yg2y22f2cs410gkuf22jyz",
    );
}
#[test]
fn mainnet_64byte() {
    // 64-byte public key hash on mainnet
    verify(
        Network::Main,
        &"D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B".from_hex().unwrap(),
        "cfx:0z8f6hhh1nah7pf03smtjy329em87tnxn3ucc243s47jhgmpftkysxzcszrenurwdpm9zbbju4dcjsf1chksr1maxvp5yb0xm24885uvnjjgpguy",
    );
}

#[test]
fn testnet_20byte() {
    // 20-byte public key hash on testnet
    verify(
        Network::Test,
        &"F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"
            .from_hex()
            .unwrap(),
        "cfxtest:03uvyj5kjzdee2z85cycmhwkz3njpv6ut4af004e99",
    );
}

#[test]
fn testnet_24byte() {
    // 24-byte public key hash on testnet
    verify(
        Network::Test,
        &"7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"
            .from_hex()
            .unwrap(),
        "cfxtest:05xdrxp1e22bt1p1e1m2fd0uavuwmcm6b4jyjhratdxfn0t2",
    );
}

#[test]
fn testnet_28byte() {
    // 28-byte public key hash on testnet
    verify(
        Network::Test,
        &"3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"
            .from_hex()
            .unwrap(),
        "cfxtest:08x89yefa6nek2hvpeksrwbac61rj2sse68jccjvzg60epsjea27vyt",
    );
}

#[test]
fn testnet_32byte() {
    // 32-byte public key hash on testnet
    verify(
        Network::Test,
        &"3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"
            .from_hex()
            .unwrap(),
        "cfxtest:0csr7vv64f3b93zx38yws36692dgm1xv8yhryhyfxx7yd7f84r060hkzn7njc",
    );
}

#[test]
fn testnet_40byte() {
    // 40-byte public key hash on testnet
    verify(
        Network::Test,
        &"C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB".from_hex().unwrap(),
        "cfxtest:0k072e1j7s0fmky14b9vgpwp53n822tz70bgce2y52dgp9b326bx355ns8wbxc9pzck0f5wyv4",
    );
}

#[test]
fn testnet_48byte() {
    // 48-byte public key hash on testnet
    verify(
        Network::Test,
        &"E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C".from_hex().unwrap(),
        "cfxtest:0rhp3jmufych0z0rmshe0hz3ehekw6efg17dcf2w833bmxhpjuws4g927p6ecapmhp33yk5hhj9gwk08cxav3r7",
    );
}

#[test]
fn testnet_56byte() {
    // 56-byte public key hash on testnet
    verify(
        Network::Test,
        &"D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041".from_hex().unwrap(),
        "cfxtest:0vczmz2cdvupvh7z88xuntpmjrdzythx0d575mewfn9crzkx3tm5hyen4ep0myjw6g3rce74vmd706yg2y22f2cs410g9cpne8en",
    );
}
#[test]
fn testnet_64byte() {
    // 64-byte public key hash on testnet
    verify(
        Network::Test,
        &"D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B".from_hex().unwrap(),
        "cfxtest:0z8f6hhh1nah7pf03smtjy329em87tnxn3ucc243s47jhgmpftkysxzcszrenurwdpm9zbbju4dcjsf1chksr1maxvp5yb0xm24885uv5wp01dyc",
    );
}

fn verify(network: Network, data: &Vec<u8>, cfx_base32_addr: &str) {
    let output =
        cfx_addr_encode(data, network, EncodingOptions::Simple).unwrap();
    assert!(
        output == cfx_base32_addr.to_ascii_lowercase(),
        "expected address {}, got {}",
        cfx_base32_addr.to_ascii_lowercase(),
        output
    );
    let decoded = cfx_addr_decode(cfx_base32_addr).unwrap();
    assert!(&decoded.body == data, "decoded address mismatch");
}
