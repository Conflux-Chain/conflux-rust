// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-cfx-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-cfx-addr.

use super::{consts::Network, *};
use rustc_hex::FromHex;

#[test]
fn spec_test_vectors() {
    verify(
        Network::Main,
        "85d80245dc02f5a89589e1f19c5c718e405b56cd",
        "cfx:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c",
    );

    verify(
        Network::Test,
        "85d80245dc02f5a89589e1f19c5c718e405b56cd",
        "cfxtest:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6",
    );

    verify(
        Network::Main,
        "1a2f80341409639ea6a35bbcab8299066109aa55",
        "cfx:00d2z01m2g4p77n6mddvtaw2k43622daamm1867uk6",
    );

    verify(
        Network::Test,
        "1a2f80341409639ea6a35bbcab8299066109aa55",
        "cfxtest:00d2z01m2g4p77n6mddvtaw2k43622daamyavp1grc",
    );

    verify(
        Network::Main,
        "19c742cec42b9e4eff3b84cdedcde2f58a36f44f",
        "cfx:00cwegpesgntwkrz7e2cvvedwbusmdrm9wdsdks47x",
    );

    verify(
        Network::Test,
        "19c742cec42b9e4eff3b84cdedcde2f58a36f44f",
        "cfxtest:00cwegpesgntwkrz7e2cvvedwbusmdrm9w7ky3ye3r",
    );

    verify(
        Network::Main,
        "84980a94d94f54ac335109393c08c866a21b1b0e",
        "cfx:0229g2mmv57n9b1ka44kjf08t1ka46sv1s1vpcf0wh",
    );

    verify(
        Network::Test,
        "84980a94d94f54ac335109393c08c866a21b1b0e",
        "cfxtest:0229g2mmv57n9b1ka44kjf08t1ka46sv1sbg5w9asv",
    );

    verify(
        Network::Main,
        "1cdf3969a428a750b89b33cf93c96560e2bd17d1",
        "cfx:00edyeb9mgmaem5skctwz4y9cnge5f8ru42rbphk8r",
    );

    verify(
        Network::Test,
        "1cdf3969a428a750b89b33cf93c96560e2bd17d1",
        "cfxtest:00edyeb9mgmaem5skctwz4y9cnge5f8ru48ws6rtcx",
    );

    verify(
        Network::Main,
        "0888000000000000000000000000000000000002",
        "cfx:0048g00000000000000000000000000008djg2z8b1",
    );

    verify(
        Network::Test,
        "0888000000000000000000000000000000000002",
        "cfxtest:0048g000000000000000000000000000087t3jt2fb",
    );
}

#[test]
fn encoding_errors() {
    // invalid input length
    let data = "85d80245dc02f5a89589e1f19c5c718e405b56"
        .from_hex::<Vec<u8>>()
        .unwrap();

    assert!(cfx_addr_encode(&data, Network::Main).is_err());
}

#[test]
#[rustfmt::skip]
fn decoding_errors() {
    // mixed case
    assert!(cfx_addr_decode("cfx:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_ok());
    assert!(cfx_addr_decode("CFX:022XG0J5VG1FBA4NH7GZ372WE6740PUPTMS36CM58C").is_ok());
    assert!(cfx_addr_decode("Cfx:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("cfx:022Xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());

    // prefix
    assert!(cfx_addr_decode("022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("bch:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("cfx1:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("cfx1029:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());

    // optional address type
    assert!(cfx_addr_decode("cfx:type.contract:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_ok());
    assert!(cfx_addr_decode("cfx:type.contract:opt.random:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_ok());
    assert!(cfx_addr_decode("cfx:type.user:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("cfx:contract:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());
    assert!(cfx_addr_decode("cfx:type.contract.2:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());

    // length check
    assert!(cfx_addr_decode("cfx:").is_err());
    assert!(cfx_addr_decode("cfx:062xg0j5vg1fba4nh7gz372we6740puptmru39kknc").is_err()); // change length in version byte to 001
    assert!(cfx_addr_decode("cfx:0022xg0j5vg1fba4nh7gz372we6740puptms36cm58c").is_err());

    // charset check
    assert!(cfx_addr_decode("cfx:022xg0i5vg1fba4nh7gz372we6740puptms36cm58c").is_err()); // j --> i

    // checksum check
    for ii in 4..46 {
        let mut x: String = "cfx:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c".into();

        // need unsafe to mutate utf-8
        unsafe {
            match &mut x.as_mut_vec()[ii] {
                ch if *ch == 48 => *ch = 49, // change '0' to '1'
                ch => *ch = 48,              // change to '0'
            };
        }

        assert!(cfx_addr_decode(&x).is_err());
    }

    // version check
    assert!(cfx_addr_decode("cfx:g22xg0j5vg1fba4nh7gz372we6740puptm91kazw6t").is_err()); // version byte: 0b10000000
    assert!(cfx_addr_decode("cfx:822xg0j5vg1fba4nh7gz372we6740puptm42sf5xfj").is_err()); // version byte: 0b01000000
    assert!(cfx_addr_decode("cfx:422xg0j5vg1fba4nh7gz372we6740puptmpr9t89z3").is_err()); // version byte: 0b00100000
    assert!(cfx_addr_decode("cfx:222xg0j5vg1fba4nh7gz372we6740puptmz9nju3rz").is_err()); // version byte: 0b00010000
    assert!(cfx_addr_decode("cfx:122xg0j5vg1fba4nh7gz372we6740puptmf6v3k6kh").is_err()); // version byte: 0b00001000
}

#[test]
fn bch_tests() {
    // 20-byte public key hash on mainnet
    verify(
        Network::Main,
        "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9",
        "cfx:03uvyj5kjzdee2z85cycmhwkz3njpv6ut404kg24d3",
    );

    // 24-byte public key hash on mainnet
    verify(
        Network::Main,
        "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA",
        "cfx:05xdrxp1e22bt1p1e1m2fd0uavuwmcm6b4jyjhrah5yarrsk",
    );

    // 28-byte public key hash on mainnet
    verify(
        Network::Main,
        "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B",
        "cfx:08x89yefa6nek2hvpeksrwbac61rj2sse68jccjvzg60epsfkmp7pfx",
    );

    // 32-byte public key hash on mainnet
    verify(
        Network::Main,
        "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060",
        "cfx:0csr7vv64f3b93zx38yws36692dgm1xv8yhryhyfxx7yd7f84r060ts1bh7b2",
    );

    // 40-byte public key hash on mainnet
    verify(
        Network::Main,
        "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB",
        "cfx:0k072e1j7s0fmky14b9vgpwp53n822tz70bgce2y52dgp9b326bx355ns8wbxc9pzc6wyh3134",
    );

    // 48-byte public key hash on mainnet
    verify(
        Network::Main,
        "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C",
        "cfx:0rhp3jmufych0z0rmshe0hz3ehekw6efg17dcf2w833bmxhpjuws4g927p6ecapmhp33yk5hhj9gwk0p7j3465g",
    );

    // 56-byte public key hash on mainnet
    verify(
        Network::Main,
        "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041",
        "cfx:0vczmz2cdvupvh7z88xuntpmjrdzythx0d575mewfn9crzkx3tm5hyen4ep0myjw6g3rce74vmd706yg2y22f2cs410gkuf22jyz",
    );

    // 64-byte public key hash on mainnet
    verify(
        Network::Main,
        "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B",
        "cfx:0z8f6hhh1nah7pf03smtjy329em87tnxn3ucc243s47jhgmpftkysxzcszrenurwdpm9zbbju4dcjsf1chksr1maxvp5yb0xm24885uvnjjgpguy",
    );

    // 20-byte public key hash on testnet
    verify(
        Network::Test,
        "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9",
        "cfxtest:03uvyj5kjzdee2z85cycmhwkz3njpv6ut4af004e99",
    );

    // 24-byte public key hash on testnet
    verify(
        Network::Test,
        "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA",
        "cfxtest:05xdrxp1e22bt1p1e1m2fd0uavuwmcm6b4jyjhratdxfn0t2",
    );

    // 28-byte public key hash on testnet
    verify(
        Network::Test,
        "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B",
        "cfxtest:08x89yefa6nek2hvpeksrwbac61rj2sse68jccjvzg60epsjea27vyt",
    );

    // 32-byte public key hash on testnet
    verify(
        Network::Test,
        "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060",
        "cfxtest:0csr7vv64f3b93zx38yws36692dgm1xv8yhryhyfxx7yd7f84r060hkzn7njc",
    );

    // 40-byte public key hash on testnet
    verify(
        Network::Test,
        "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB",
        "cfxtest:0k072e1j7s0fmky14b9vgpwp53n822tz70bgce2y52dgp9b326bx355ns8wbxc9pzck0f5wyv4",
    );

    // 48-byte public key hash on testnet
    verify(
        Network::Test,
        "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C",
        "cfxtest:0rhp3jmufych0z0rmshe0hz3ehekw6efg17dcf2w833bmxhpjuws4g927p6ecapmhp33yk5hhj9gwk08cxav3r7",
    );

    // 56-byte public key hash on testnet
    verify(
        Network::Test,
        "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041",
        "cfxtest:0vczmz2cdvupvh7z88xuntpmjrdzythx0d575mewfn9crzkx3tm5hyen4ep0myjw6g3rce74vmd706yg2y22f2cs410g9cpne8en",
    );

    // 64-byte public key hash on testnet
    verify(
        Network::Test,
        "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B",
        "cfxtest:0z8f6hhh1nah7pf03smtjy329em87tnxn3ucc243s47jhgmpftkysxzcszrenurwdpm9zbbju4dcjsf1chksr1maxvp5yb0xm24885uv5wp01dyc",
    );
}

fn verify(network: Network, data: &str, base32addr: &str) {
    let data: Vec<u8> = data.from_hex().unwrap();
    let output = cfx_addr_encode(&data, network).unwrap();
    assert_eq!(output, base32addr);

    let decoded = cfx_addr_decode(base32addr).unwrap();
    assert_eq!(decoded.body, data, "decoded address mismatch");
    assert_eq!(decoded.network, network, "decoded network mismatch");
}
