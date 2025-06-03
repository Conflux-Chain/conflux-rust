use rlp::{DecoderError, Rlp};

/// Decode a boolean from RLP
/// This function handles both new and legacy RLP boolean encodings.
/// - New format (rlp 0.5+): true is encoded as 0x01, false as 0x80(empty
///   string).
/// - Legacy format: false is encoded as 0x00.
pub fn rlp_decode_bool_compat(item: &Rlp) -> Result<bool, DecoderError> {
    match <bool as rlp::Decodable>::decode(item) {
        Ok(value) => Ok(value),
        Err(DecoderError::RlpInvalidIndirection) => {
            // Handle legacy encoding: 0x00 represents false
            // see: https://github.com/paritytech/parity-common/blob/master/rlp/src/impls.rs#L159
            let data = item.data()?;
            if data.len() == 1 && data[0] == 0x00 {
                Ok(false)
            } else {
                Err(DecoderError::RlpInvalidIndirection)
            }
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_compatible_bool() {
        let rlp_true = Rlp::new(&[0x01]);
        assert_eq!(rlp_decode_bool_compat(&rlp_true).unwrap(), true);

        let rlp_false = Rlp::new(&[0x80]);
        assert_eq!(rlp_decode_bool_compat(&rlp_false).unwrap(), false);

        // test legacy encoding
        let rlp_false_legacy = Rlp::new(&[0x00]);
        assert_eq!(rlp_decode_bool_compat(&rlp_false_legacy).unwrap(), false);
    }
}
