//! Wrapper types that pin the RLP wire format across `rlp` crate version
//! changes. Apply them at serialization boundaries so consensus hashes and
//! P2P message bytes stay stable regardless of which `rlp` is linked.
//!
//! Currently covers `bool` — the only wire-format change between rlp 0.4
//! and 0.6 (see rlp 0.5.1 CHANGELOG / parity-common #572). For the
//! conflux-rust project alias naming the Phase 1/Phase 2 choice, see
//! `primitives::CompatBool`.

use std::iter::once;

use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

// rlp 0.4's `bool` encoding.
fn encode_04(b: bool, s: &mut RlpStream) {
    s.encoder().encode_iter(once(if b { 1u8 } else { 0u8 }));
}

/// Encodes `0x00`/`0x01`, decodes `0x00`/`0x01` only. Reject-on-drift for
/// consensus-critical fields: non-canonical encoding on the wire could
/// cause chain splits if accepted.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct StrictBool(pub bool);

impl Encodable for StrictBool {
    fn rlp_append(&self, s: &mut RlpStream) { encode_04(self.0, s); }
}

impl Decodable for StrictBool {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes {
            [0] => Ok(StrictBool(false)),
            [1] => Ok(StrictBool(true)),
            _ => Err(DecoderError::Custom("expected 0x00 or 0x01")),
        })
    }
}

/// Encodes like rlp 0.4 (`false` → `0x00`), decodes permissively
/// (`0x00`/`0x01`/`0x80`) so peers on either side of the encoding change
/// stay interoperable.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct CompatBool04(pub bool);

impl Encodable for CompatBool04 {
    fn rlp_append(&self, s: &mut RlpStream) { encode_04(self.0, s); }
}

impl Decodable for CompatBool04 {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes {
            [] | [0] => Ok(CompatBool04(false)),
            [1] => Ok(CompatBool04(true)),
            _ => Err(DecoderError::Custom("expected 0x00, 0x01, or 0x80")),
        })
    }
}

/// Encodes like rlp 0.6 (`false` → `0x80`), decodes permissively (same as
/// `CompatBool04`). Phase 2 target; point `primitives::CompatBool` here
/// once peers accept `0x80`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct CompatBool06(pub bool);

impl Encodable for CompatBool06 {
    // Mirrors rlp 0.5.1+'s `bool`, which delegates to `u8`. `u8` encoding
    // is identical between rlp 0.4 and 0.6, so output is stable.
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_internal(&(self.0 as u8));
    }
}

impl Decodable for CompatBool06 {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes {
            [] | [0] => Ok(CompatBool06(false)),
            [1] => Ok(CompatBool06(true)),
            _ => Err(DecoderError::Custom("expected 0x00, 0x01, or 0x80")),
        })
    }
}

#[cfg(test)]
mod tests {
    //! `rlp::` is the main dep (0.4 today); `rlp_06` is a dev-dep alias
    //! to rlp 0.6. After the main `rlp` upgrade to 0.6, flip the dev-dep
    //! to `rlp_04` and rewrite `rlp::` → `rlp_04::` on the 0.4 side.

    use super::*;

    fn encode<T: Encodable>(v: &T) -> Vec<u8> { rlp::encode(v).to_vec() }
    fn decode<T: Decodable>(bytes: &[u8]) -> Result<T, DecoderError> {
        rlp::decode(bytes)
    }

    // --- Encode ---

    #[test]
    fn encode_absolute_bytes() {
        assert_eq!(encode(&StrictBool(false)), vec![0x00]);
        assert_eq!(encode(&StrictBool(true)), vec![0x01]);
        assert_eq!(encode(&CompatBool04(false)), vec![0x00]);
        assert_eq!(encode(&CompatBool04(true)), vec![0x01]);
        assert_eq!(encode(&CompatBool06(false)), vec![0x80]);
        assert_eq!(encode(&CompatBool06(true)), vec![0x01]);
    }

    // Cross-checks against the ambient native impls, documenting which
    // rlp version each wrapper's encoding mirrors.

    #[test]
    fn compat_bool_04_encode_matches_rlp_04() {
        assert_eq!(encode(&CompatBool04(false)), rlp::encode(&false).to_vec());
        assert_eq!(encode(&CompatBool04(true)), rlp::encode(&true).to_vec());
    }

    #[test]
    fn compat_bool_06_encode_matches_rlp_06() {
        assert_eq!(
            encode(&CompatBool06(false)),
            rlp_06::encode(&false).to_vec()
        );
        assert_eq!(encode(&CompatBool06(true)), rlp_06::encode(&true).to_vec());
    }

    #[test]
    fn strict_bool_encode_matches_rlp_04() {
        assert_eq!(encode(&StrictBool(false)), rlp::encode(&false).to_vec());
        assert_eq!(encode(&StrictBool(true)), rlp::encode(&true).to_vec());
    }

    // Decode behavior for each payload `[b]`:
    //
    //   b       rlp_04  rlp_06  StrictBool  CompatBool04  CompatBool06
    //   -----   ------  ------  ----------  ------------  ------------
    //   empty   false   false   Err         false         false
    //   0x00    false   Err     false       false         false
    //   0x01    true    true    true        true          true
    //   other   true    Err     Err         Err           Err

    #[test]
    fn decode_empty_payload() {
        assert_eq!(rlp::decode::<bool>(&[0x80]).unwrap(), false);
        assert_eq!(rlp_06::decode::<bool>(&[0x80]).unwrap(), false);

        assert!(decode::<StrictBool>(&[0x80]).is_err());
        assert_eq!(
            decode::<CompatBool04>(&[0x80]).unwrap(),
            CompatBool04(false)
        );
        assert_eq!(
            decode::<CompatBool06>(&[0x80]).unwrap(),
            CompatBool06(false)
        );
    }

    #[test]
    fn decode_zero_byte() {
        assert_eq!(rlp::decode::<bool>(&[0x00]).unwrap(), false);
        assert!(rlp_06::decode::<bool>(&[0x00]).is_err());

        assert_eq!(decode::<StrictBool>(&[0x00]).unwrap(), StrictBool(false));
        assert_eq!(
            decode::<CompatBool04>(&[0x00]).unwrap(),
            CompatBool04(false)
        );
        assert_eq!(
            decode::<CompatBool06>(&[0x00]).unwrap(),
            CompatBool06(false)
        );
    }

    #[test]
    fn decode_one_byte() {
        assert_eq!(rlp::decode::<bool>(&[0x01]).unwrap(), true);
        assert_eq!(rlp_06::decode::<bool>(&[0x01]).unwrap(), true);

        assert_eq!(decode::<StrictBool>(&[0x01]).unwrap(), StrictBool(true));
        assert_eq!(
            decode::<CompatBool04>(&[0x01]).unwrap(),
            CompatBool04(true)
        );
        assert_eq!(
            decode::<CompatBool06>(&[0x01]).unwrap(),
            CompatBool06(true)
        );
    }

    #[test]
    fn decode_other_single_bytes_exhaustive() {
        // Every single-byte payload value other than 0 and 1. rlp 0.4 maps
        // these to true; rlp 0.6 and all our wrappers reject.
        for byte in 2u8..=0xff {
            let rlp_bytes: Vec<u8> = if byte < 0x80 {
                vec![byte]
            } else {
                vec![0x81, byte]
            };

            assert_eq!(
                rlp::decode::<bool>(&rlp_bytes).unwrap(),
                true,
                "rlp_04 byte {:#04x}",
                byte
            );
            assert!(
                rlp_06::decode::<bool>(&rlp_bytes).is_err(),
                "rlp_06 byte {:#04x}",
                byte
            );

            assert!(decode::<StrictBool>(&rlp_bytes).is_err());
            assert!(decode::<CompatBool04>(&rlp_bytes).is_err());
            assert!(decode::<CompatBool06>(&rlp_bytes).is_err());
        }
    }

    #[test]
    fn decode_multi_byte_payloads_rejected_everywhere() {
        for rlp_bytes in
            [&[0x82, 0xab, 0xcd][..], &[0x83, 0x01, 0x02, 0x03][..]]
        {
            assert!(rlp::decode::<bool>(rlp_bytes).is_err());
            assert!(rlp_06::decode::<bool>(rlp_bytes).is_err());
            assert!(decode::<StrictBool>(rlp_bytes).is_err());
            assert!(decode::<CompatBool04>(rlp_bytes).is_err());
            assert!(decode::<CompatBool06>(rlp_bytes).is_err());
        }
    }

    #[test]
    fn round_trip() {
        for v in [false, true] {
            assert_eq!(
                decode::<StrictBool>(&encode(&StrictBool(v))).unwrap().0,
                v
            );
            assert_eq!(
                decode::<CompatBool04>(&encode(&CompatBool04(v))).unwrap().0,
                v
            );
            assert_eq!(
                decode::<CompatBool06>(&encode(&CompatBool06(v))).unwrap().0,
                v
            );
        }
    }
}
