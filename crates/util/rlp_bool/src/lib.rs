// Wrapper types that pin the RLP encoding of booleans across the rlp 0.4 →
// 0.6+ upgrade. In rlp 0.4, `<bool as Encodable>` emits `0x00` for `false`; in
// rlp 0.6 it delegates to `<u8 as Encodable>`, which emits the empty-string
// marker `0x80`. These wrappers decouple our wire format from that change.
//
// See issue #3254 for the phased plan.

use std::iter::once;

use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

fn encode_legacy(b: bool, s: &mut RlpStream) {
    let byte: u8 = if b { 1 } else { 0 };
    s.encoder().encode_iter(once(byte));
}

/// Boolean wrapper for consensus-critical fields: encodes `0x00`/`0x01`, and
/// **rejects `0x80`** on decode. Strict decoding is a defensive measure
/// against future consensus fields where non-canonical encoding on the wire
/// could cause chain splits.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct StrictBool(pub bool);

impl Encodable for StrictBool {
    fn rlp_append(&self, s: &mut RlpStream) { encode_legacy(self.0, s); }
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

/// Boolean wrapper for P2P / DB / trace fields in Phase 1 of the migration:
/// encodes legacy (`0x00`/`0x01`) but accepts `0x80` on decode. Permissive
/// decoding lets peers still read our messages after a future Phase 2 where
/// the encoder switches to the rlp 0.6 standard (`false` → `0x80`).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, DeriveMallocSizeOf,
)]
pub struct CompatBool(pub bool);

impl Encodable for CompatBool {
    // Phase 2 transition: replace the body with `self.0.rlp_append(s)` to emit
    // `0x80` for `false` (rlp 0.6+ standard). Call sites don't change.
    fn rlp_append(&self, s: &mut RlpStream) { encode_legacy(self.0, s); }
}

impl Decodable for CompatBool {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes {
            [] | [0] => Ok(CompatBool(false)),
            [1] => Ok(CompatBool(true)),
            _ => Err(DecoderError::Custom("expected 0x00, 0x01, or 0x80")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: Encodable>(v: &T) -> Vec<u8> { rlp::encode(v).to_vec() }

    fn decode<T: Decodable>(bytes: &[u8]) -> Result<T, DecoderError> {
        rlp::decode(bytes)
    }

    // The core invariant: wrappers produce byte-identical output to the
    // current rlp 0.4 native `bool`, so swapping them in preserves the wire
    // format and consensus hashes.
    #[test]
    fn wrappers_match_rlp_04_bool_encoding() {
        assert_eq!(encode(&StrictBool(false)), encode(&false));
        assert_eq!(encode(&StrictBool(true)), encode(&true));
        assert_eq!(encode(&CompatBool(false)), encode(&false));
        assert_eq!(encode(&CompatBool(true)), encode(&true));
    }

    #[test]
    fn strict_bool_rejects_non_canonical() {
        assert_eq!(decode::<StrictBool>(&[0x00]).unwrap(), StrictBool(false));
        assert_eq!(decode::<StrictBool>(&[0x01]).unwrap(), StrictBool(true));
        assert!(decode::<StrictBool>(&[0x80]).is_err());
        assert!(decode::<StrictBool>(&[0x02]).is_err());
    }

    #[test]
    fn compat_bool_accepts_legacy_and_phase2() {
        assert_eq!(decode::<CompatBool>(&[0x00]).unwrap(), CompatBool(false));
        assert_eq!(decode::<CompatBool>(&[0x01]).unwrap(), CompatBool(true));
        assert_eq!(decode::<CompatBool>(&[0x80]).unwrap(), CompatBool(false));
        assert!(decode::<CompatBool>(&[0x02]).is_err());
    }
}
