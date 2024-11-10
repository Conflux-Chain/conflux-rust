// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.
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
