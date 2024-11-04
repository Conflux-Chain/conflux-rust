use cfx_addr::*;
use rustc_hex::FromHex;

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
