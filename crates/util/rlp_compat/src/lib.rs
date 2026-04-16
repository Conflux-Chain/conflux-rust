//! Wrapper types that pin the RLP wire format for types whose `Encodable` /
//! `Decodable` impls have changed across `rlp` crate versions.
//!
//! Consensus hashes and P2P message formats depend on byte-for-byte wire
//! stability, so any `rlp` upgrade that shifts an impl's output is a
//! consensus or protocol break. This crate decouples our wire format from
//! the underlying `rlp` version: apply the wrappers at serialization
//! boundaries and the encoded/decoded bytes stay stable regardless of which
//! `rlp` version is linked.
//!
//! Currently covers `bool` — the only wire-format incompatibility between
//! rlp 0.4 and 0.6 (see rlp 0.5.1 CHANGELOG / parity-common #572).

use std::iter::{empty, once};

use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// Boolean wrapper for consensus-critical fields.
///
/// - Encodes `false` as `0x00`, `true` as `0x01`.
/// - Decodes `0x00`/`0x01` only; **rejects `0x80`** and any other encoding.
///
/// Strict decoding is a defensive measure against future consensus bool
/// fields where non-canonical encoding on the wire could cause chain splits.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct StrictBool(pub bool);

impl Encodable for StrictBool {
    fn rlp_append(&self, s: &mut RlpStream) {
        let byte: u8 = if self.0 { 1 } else { 0 };
        s.encoder().encode_iter(once(byte));
    }
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

/// Boolean wrapper matching rlp 0.4's `bool` encoding (`false` → `0x00`).
///
/// - Encodes like rlp 0.4's native `bool`.
/// - Decodes permissively: accepts `0x00`, `0x01`, and `0x80` (the encoding rlp
///   0.5.1+ emits for `false`), so peers on either side of the encoding change
///   stay interoperable.
///
/// This is the Phase 1 type: we encode legacy and decode either, letting
/// the network roll over to permissive decoders before any node switches
/// encoder output.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct CompatBool04(pub bool);

impl Encodable for CompatBool04 {
    fn rlp_append(&self, s: &mut RlpStream) {
        let byte: u8 = if self.0 { 1 } else { 0 };
        s.encoder().encode_iter(once(byte));
    }
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

/// Boolean wrapper matching rlp 0.6's `bool` encoding (`false` → `0x80`).
///
/// - Encodes like rlp 0.6's native `bool`: `false` as the empty-string marker
///   `0x80`, `true` as `0x01`.
/// - Decodes permissively, identical to `CompatBool04`.
///
/// Not wired into any field in this PR. Reserved for the future Phase 2
/// transition: swapping a `CompatBool04` call site to `CompatBool06` flips
/// the emitted encoding while peers running Phase 1 still decode
/// successfully.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct CompatBool06(pub bool);

impl Encodable for CompatBool06 {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.0 {
            s.encoder().encode_iter(once(1u8));
        } else {
            s.encoder().encode_iter(empty());
        }
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
    //! Tests compare our wrappers against both rlp 0.4 and rlp 0.6 native
    //! `bool` impls side-by-side. The main `rlp` dependency is 0.4 today
    //! (referenced below as `rlp`); `rlp_06` is a dev-dep alias to rlp 0.6.
    //! After the upgrade bumps the main `rlp` to 0.6, the dev-dep should
    //! flip to `rlp_04 = { package = "rlp", version = "0.4" }` and the
    //! `rlp::` references for the 0.4 side swap to `rlp_04::`.

    use super::*;

    fn encode<T: Encodable>(v: &T) -> Vec<u8> { rlp::encode(v).to_vec() }
    fn decode<T: Decodable>(bytes: &[u8]) -> Result<T, DecoderError> {
        rlp::decode(bytes)
    }

    // --- Encode: byte-for-byte match against the matching native impl ---

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
        // StrictBool's encode output is identical to rlp 0.4's; it differs
        // from both versions only on decode (stricter than either).
        assert_eq!(encode(&StrictBool(false)), rlp::encode(&false).to_vec());
        assert_eq!(encode(&StrictBool(true)), rlp::encode(&true).to_vec());
    }

    // --- Decode: behavior matrix vs both native versions ---
    //
    // For each single-byte payload `[b]`:
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
