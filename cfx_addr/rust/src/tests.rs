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
        "cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp",
    );

    verify(
        Network::Test,
        "85d80245dc02f5a89589e1f19c5c718e405b56cd",
        "cfxtest:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg",
    );

    verify(
        Network::Main,
        "1a2f80341409639ea6a35bbcab8299066109aa55",
        "cfx:aarc9abycue0hhzgyrr53m6cxedgccrmmyybjgh4xg",
    );

    verify(
        Network::Test,
        "1a2f80341409639ea6a35bbcab8299066109aa55",
        "cfxtest:aarc9abycue0hhzgyrr53m6cxedgccrmmy8m50bu1p",
    );

    verify(
        Network::Main,
        "19c742cec42b9e4eff3b84cdedcde2f58a36f44f",
        "cfx:aap6su0s2uz36x19hscp55sr6n42yr1yk6r2rx2eh7",
    );

    verify(
        Network::Test,
        "19c742cec42b9e4eff3b84cdedcde2f58a36f44f",
        "cfxtest:aap6su0s2uz36x19hscp55sr6n42yr1yk6hx8d8sd1",
    );

    verify(
        Network::Main,
        "84980a94d94f54ac335109393c08c866a21b1b0e",
        "cfx:acckucyy5fhzknbxmeexwtaj3bxmeg25b2b50pta6v",
    );

    verify(
        Network::Test,
        "84980a94d94f54ac335109393c08c866a21b1b0e",
        "cfxtest:acckucyy5fhzknbxmeexwtaj3bxmeg25b2nuf6km25",
    );

    verify(
        Network::Main,
        "1cdf3969a428a750b89b33cf93c96560e2bd17d1",
        "cfx:aasr8snkyuymsyf2xp369e8kpzusftj14ec1n0vxj1",
    );

    verify(
        Network::Test,
        "1cdf3969a428a750b89b33cf93c96560e2bd17d1",
        "cfxtest:aasr8snkyuymsyf2xp369e8kpzusftj14ej62g13p7",
    );

    verify(
        Network::Main,
        "0888000000000000000000000000000000000002",
        "cfx:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajrwuc9jnb",
    );

    verify(
        Network::Test,
        "0888000000000000000000000000000000000002",
        "cfxtest:aaejuaaaaaaaaaaaaaaaaaaaaaaaaaaaajh3dw3ctn",
    );
}

#[test]
fn encoding_errors() {
    // invalid input length
    let data = "85d80245dc02f5a89589e1f19c5c718e405b56"
        .from_hex::<Vec<u8>>()
        .unwrap();

    assert!(
        cfx_addr_encode(&data, Network::Main, EncodingOptions::Simple).is_err()
    );
}

#[test]
#[rustfmt::skip]
fn decoding_errors() {
    let hex_addr = "85d80245dc02f5a89589e1f19c5c718e405b56cd".from_hex::<Vec<u8>>().unwrap();
    let base32_addr = cfx_addr_encode(&hex_addr, Network::Main, EncodingOptions::Simple).unwrap();
    assert_eq!(base32_addr, "cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp");

    // mixed case
    assert!(cfx_addr_decode("cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_ok());
    assert!(cfx_addr_decode("CFX:ACC7UAWF5UBTNMEZVHU9DHC6SGHEA0403Y2DGPYFJP").is_ok());
    assert!(cfx_addr_decode("Cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("cfx:acc7Uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());

    // prefix
    assert!(cfx_addr_decode("acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("bch:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("cfx1:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("cfx1029:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());

    // optional address type
    assert!(cfx_addr_decode("cfx:type.contract:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_ok());
    assert!(cfx_addr_decode("cfx:type.contract:opt.random:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_ok());
    assert!(cfx_addr_decode("cfx:type.user:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("cfx:contract:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());
    assert!(cfx_addr_decode("cfx:type.contract.2:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());

    // length check
    assert!(cfx_addr_decode("cfx:").is_err());
    assert!(cfx_addr_decode("cfx:agc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err()); // change length in version byte to 001
    assert!(cfx_addr_decode("cfx:aacc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err());

    // charset check
    assert!(cfx_addr_decode("cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfip").is_err()); // j --> i

    // checksum check
    for ii in 4..46 {
        let mut x = base32_addr.clone();

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
    assert!(cfx_addr_decode("cfx:t22xg0j5vg1fba4nh7gz372we6740puptm91kazw6t").is_err()); // version byte: 0b10000000
    assert!(cfx_addr_decode("cfx:jcc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err()); // version byte: 0b01000000
    assert!(cfx_addr_decode("cfx:ecc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err()); // version byte: 0b00100000
    assert!(cfx_addr_decode("cfx:ccc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err()); // version byte: 0b00010000
    assert!(cfx_addr_decode("cfx:bcc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp").is_err()); // version byte: 0b00001000
}

#[test]
fn bch_tests() {
    // 20-byte public key hash on mainnet
    verify(
        Network::Main,
        "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9",
        "cfx:ad458wfxw9rssc9jfp8pyv6x9dzw05g43eaexucerd",
    );

    // 24-byte public key hash on mainnet
    verify(
        Network::Main,
        "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA",
        "cfx:af7r170bsccn3b0bsbyctra4m546ypygnew8wv1mvf8m112x",
    );

    // 28-byte public key hash on mainnet
    verify(
        Network::Main,
        "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B",
        "cfx:aj7jk8stmgzsxcv50sx216nmpgb1wc22sgjwppw59ugas02txy0h0t7",
    );

    // 32-byte public key hash on mainnet
    verify(
        Network::Main,
        "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060",
        "cfx:ap21h55getdnkd97dj862dggkcruyb75j8v18v8t77h8rhtje1aga32bnvhnc",
    );

    // 40-byte public key hash on mainnet
    verify(
        Network::Main,
        "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB",
        "cfx:axahcsbwh2atyx8benk5u060fdzjcc39hanupsc8fcru0kndcgn7dffz2j6n7pk09pg68vdbde",
    );

    // 48-byte public key hash on mainnet
    verify(
        Network::Main,
        "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C",
        "cfx:a1v0dwy4t8pva9a1y2vsav9dsvsx6gstubhrptc6jddny7v0w462eukch0gspm0yv0dd8xfvvwku6xa0hwdegfu",
    );

    // 56-byte public key hash on mainnet
    verify(
        Network::Main,
        "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041",
        "cfx:a5p9y9cpr5405vh9jj74z30yw1r983v7arfhfys6tzkp19x7d3yfv8szes0ay8w6gud1pshe5yrhag8uc8cctcp2ebaux4tccw89",
    );

    // 64-byte public key hash on mainnet
    verify(
        Network::Main,
        "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B",
        "cfx:a9jtgvvvbzmvh0tad2y3w8dcksyjh3z7zd4ppced2ehwvuy0t3x8279p291sz416r0yk9nnw4erpw2tbpvx21bym750f8na7ycejjf45zwwu0u48",
    );

    // 20-byte public key hash on testnet
    verify(
        Network::Test,
        "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9",
        "cfxtest:ad458wfxw9rssc9jfp8pyv6x9dzw05g43emtaaeskk",
    );

    // 24-byte public key hash on testnet
    verify(
        Network::Test,
        "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA",
        "cfxtest:af7r170bsccn3b0bsbyctra4m546ypygnew8wv1m3r7tza3c",
    );

    // 28-byte public key hash on testnet
    verify(
        Network::Test,
        "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B",
        "cfxtest:aj7jk8stmgzsxcv50sx216nmpgb1wc22sgjwppw59ugas02wsmch583",
    );

    // 32-byte public key hash on testnet
    verify(
        Network::Test,
        "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060",
        "cfxtest:ap21h55getdnkd97dj862dggkcruyb75j8v18v8t77h8rhtje1agavx9zhzwp",
    );

    // 40-byte public key hash on testnet
    verify(
        Network::Test,
        "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB",
        "cfxtest:axahcsbwh2atyx8benk5u060fdzjcc39hanupsc8fcru0kndcgn7dffz2j6n7pk09pxatf685e",
    );

    // 48-byte public key hash on testnet
    verify(
        Network::Test,
        "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C",
        "cfxtest:a1v0dwy4t8pva9a1y2vsav9dsvsx6gstubhrptc6jddny7v0w462eukch0gspm0yv0dd8xfvvwku6xajp7m5d1h",
    );

    // 56-byte public key hash on testnet
    verify(
        Network::Test,
        "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041",
        "cfxtest:a5p9y9cpr5405vh9jj74z30yw1r983v7arfhfys6tzkp19x7d3yfv8szes0ay8w6gud1pshe5yrhag8uc8cctcp2ebaukp0zsjsz",
    );

    // 64-byte public key hash on testnet
    verify(
        Network::Test,
        "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B",
        "cfxtest:a9jtgvvvbzmvh0tad2y3w8dcksyjh3z7zd4ppced2ehwvuy0t3x8279p291sz416r0yk9nnw4erpw2tbpvx21bym750f8na7ycejjf45f60abr8p",
    );
}

fn verify(network: Network, data: &str, base32addr: &str) {
    let data: Vec<u8> = data.from_hex().unwrap();
    let output =
        cfx_addr_encode(&data, network, EncodingOptions::Simple).unwrap();
    assert_eq!(output, base32addr);

    let decoded = cfx_addr_decode(base32addr).unwrap();
    assert_eq!(decoded.bytes, data, "decoded address mismatch");
    assert_eq!(decoded.network, network, "decoded network mismatch");
}
