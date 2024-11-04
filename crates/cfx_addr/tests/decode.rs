use cfx_addr::*;
use rustc_hex::FromHex;

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
