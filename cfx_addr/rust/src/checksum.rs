// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
//
// Modification based on https://github.com/hlb8122/rust-bitcoincash-addr in MIT License.
// A copy of the original license is included in LICENSE.rust-bitcoincash-addr.

// https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#checksum
pub fn polymod(v: &[u8]) -> u64 {
    let mut c = 1;
    for d in v {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07ffffffff) << 5) ^ u64::from(*d);
        if c0 & 0x01 != 0 {
            c ^= 0x98f2bc8e61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x79b76d99e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0xf33e5fb3c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0xae2eabe2a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x1e4f43e470;
        }
    }
    c ^ 1
}
