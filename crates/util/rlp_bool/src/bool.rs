use std::iter::once;

use rlp::{Decodable, Encodable};

/// Legacy boolean type for RLP encoding:
/// - encodes `true` as `0x01` and `false` as `0x00`.
/// - decodes `0x01` as `true`, `0x00` as `false`
/// - any other value is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyBool(pub bool);

impl Encodable for LegacyBool {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let byte_to_encode = if self.0 { 1u8 } else { 0u8 };
        s.encoder().encode_iter(once(byte_to_encode));
    }
}

impl Decodable for LegacyBool {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes.len() {
            0 => Ok(LegacyBool(false)),
            1 => match bytes[0] {
                0 => Ok(LegacyBool(false)),
                1 => Ok(LegacyBool(true)),
                _ => Err(rlp::DecoderError::RlpInvalidIndirection),
            },
            _ => Err(rlp::DecoderError::RlpIsTooBig),
        })
    }
}

/// Compatible boolean type for RLP encoding:
/// - encodes `true` as `0x01` and `false` as `0x80`.
/// - decodes `0x01` as `true`, `0x80` as `false`, and `0x00` as `false` (legacy behavior).
/// - any other value is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibleBool(pub bool);

impl Encodable for CompatibleBool {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let as_uint = u8::from(self.0);
        Encodable::rlp_append(&as_uint, s);
    }
}

impl Decodable for CompatibleBool {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        rlp.decoder().decode_value(|bytes| match bytes.len() {
            0 => Ok(CompatibleBool(false)),
            1 => match bytes[0] {
                0 => Ok(CompatibleBool(false)),
                1 => Ok(CompatibleBool(true)),
                _ => Err(rlp::DecoderError::RlpInvalidIndirection),
            },
            _ => Err(rlp::DecoderError::RlpIsTooBig),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlp::{Rlp, RlpStream};

    #[test]
    fn test_legacy_bool() {
        let mut s = RlpStream::new();
        LegacyBool(true).rlp_append(&mut s);
        assert_eq!(s.out(), vec![0x01]);

        let mut s = RlpStream::new();
        LegacyBool(false).rlp_append(&mut s);
        assert_eq!(s.out(), vec![0x00]);

        // 0x01 => true
        assert_eq!(
            LegacyBool::decode(&Rlp::new(&[0x01])).unwrap(),
            LegacyBool(true)
        );
        // 0x00 => false
        assert_eq!(
            LegacyBool::decode(&Rlp::new(&[0x00])).unwrap(),
            LegacyBool(false)
        );

        assert!(LegacyBool::decode(&Rlp::new(&[0x02])).is_err());
        assert!(LegacyBool::decode(&Rlp::new(&[0xff])).is_err());
    }

    #[test]
    fn test_compatible_bool() {
        let mut s = RlpStream::new();
        CompatibleBool(true).rlp_append(&mut s);
        assert_eq!(s.out(), vec![0x01]);

        let mut s = RlpStream::new();
        CompatibleBool(false).rlp_append(&mut s);
        assert_eq!(s.out(), vec![0x80]);

        // 0x01 => true
        assert_eq!(
            CompatibleBool::decode(&Rlp::new(&[0x01])).unwrap(),
            CompatibleBool(true)
        );

        // 0x80 => false
        assert_eq!(
            CompatibleBool::decode(&Rlp::new(&[0x80])).unwrap(),
            CompatibleBool(false)
        );
        // // 0x00 => false (legacy behavior)
        assert_eq!(
            CompatibleBool::decode(&Rlp::new(&[0x00])).unwrap(),
            CompatibleBool(false)
        );

        // don't accept other values
        assert!(CompatibleBool::decode(&Rlp::new(&[0x02])).is_err());
        assert!(CompatibleBool::decode(&Rlp::new(&[0xff])).is_err());
    }

    #[test]
    fn test_compatibility() {
        let mut s = RlpStream::new();
        LegacyBool(false).rlp_append(&mut s);

        assert_eq!(
            CompatibleBool::decode(&Rlp::new(&s.out())).unwrap(),
            CompatibleBool(false)
        );
    }
}
