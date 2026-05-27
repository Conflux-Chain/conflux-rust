// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{utils::abi_require, ABIDecodeError, ABIVariable, LinkedBytes};
use cfx_types::{Address, H256, U256};

impl ABIVariable for Address {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(Address::from_slice(&data[12..32]))
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 12];
        answer.extend_from_slice(self.as_bytes());
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.to_fixed_bytes().into())
    }
}

impl ABIVariable for U256 {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(U256::from_big_endian(&data))
    }

    fn to_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.to_big_endian().to_vec())
    }

    fn to_packed_abi(&self) -> LinkedBytes { self.to_abi() }
}

impl ABIVariable for H256 {
    const BASIC_TYPE: bool = <[u8; 32]>::BASIC_TYPE;
    const STATIC_LENGTH: Option<usize> = <[u8; 32]>::STATIC_LENGTH;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        Ok(H256::from(<[u8; 32]>::from_abi(data)?))
    }

    fn to_abi(&self) -> LinkedBytes { self.0.to_abi() }

    fn to_packed_abi(&self) -> LinkedBytes { self.0.to_packed_abi() }
}

impl ABIVariable for bool {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(data[31] != 0)
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 32];
        answer[31] = *self as u8;
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(vec![*self as u8])
    }
}

macro_rules! impl_abi_variable_for_primitive {
    () => {};
    ($ty: ident) => {impl_abi_variable_for_primitive!($ty,);};
    ($ty: ident, $($rest: ident),*) => {
        impl ABIVariable for $ty {
            const BASIC_TYPE: bool = true;
            const STATIC_LENGTH: Option<usize> = Some(32);

            /// Decode a fixed-size unsigned integer from a 32-byte ABI word.
            ///
            /// ⚠️ **Non-strict decoding (intentional, consensus-critical).**
            ///
            /// Only validates the 32-byte length and takes the low `BITS/8` bytes;
            /// high-order bytes are **silently ignored even if non-zero**.
            ///
            /// This deviates from Solidity/EVM ABI semantics, which require
            /// `value < 2^N` for `uintN` (`N < 256`) and revert otherwise. The same
            /// calldata may therefore be interpreted differently:
            ///   - Solidity: reverts on non-zero high bytes.
            ///   - Conflux built-in: accepts the call with the truncated low value.
            ///
            /// **Caller obligations.** Built-in functions taking sub-256-bit integers
            /// via this trait MUST perform their own range/overflow checks
            /// (`checked_add`, `U256` widening, explicit bounds, etc.) and MUST NOT
            /// assume the decoder has clamped the value. Treat the ABI-level type as
            /// advisory only.
            ///
            /// See `tests_basic::test_*_truncates_high_bytes` for pinned behavior.
            fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
                const BYTES: usize = ($ty::BITS/8) as usize;
                abi_require(data.len() == 32, "Invalid call data length")?;
                let mut bytes = [0u8; BYTES];
                bytes.copy_from_slice(&data[32 - BYTES..]);
                Ok($ty::from_be_bytes(bytes))
            }

            fn to_abi(&self) -> LinkedBytes {
                const BYTES: usize = ($ty::BITS/8) as usize;
                let mut answer = vec![0u8; 32];
                answer[32 - BYTES..].copy_from_slice(&self.to_be_bytes());
                LinkedBytes::from_bytes(answer)
            }

            fn to_packed_abi(&self) -> LinkedBytes {
                LinkedBytes::from_bytes(self.to_be_bytes().to_vec())
            }
        }

        impl_abi_variable_for_primitive!($($rest),*);
    }
}

impl_abi_variable_for_primitive!(U8, u16, u32, u64, u128);

#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct U8(u8);

impl U8 {
    #[allow(dead_code)]
    const BITS: usize = 8;

    #[allow(dead_code)]
    fn to_be_bytes(self) -> [u8; 1] { [self.0] }

    #[allow(dead_code)]
    fn from_be_bytes(input: [u8; 1]) -> Self { U8(input[0]) }
}

#[cfg(test)]
mod tests_basic {
    use super::{U8, *};
    use crate::ABIVariable;

    #[test]
    fn test_packed_encoding() {
        let num = 0xDEADBEEFu32;
        let packed = num.to_packed_abi().to_vec();
        let expected = num.to_be_bytes().to_vec();
        assert_eq!(packed, expected);
    }

    #[test]
    fn test_u256_abi_basic() {
        assert!(U256::BASIC_TYPE);
        assert_eq!(U256::STATIC_LENGTH, Some(32));
    }

    #[test]
    fn test_u256_packed_abi_consistency() {
        let num = U256::max_value();
        let abi = num.to_abi();
        let packed_abi = num.to_packed_abi();
        assert_eq!(abi.to_vec(), packed_abi.to_vec());
    }

    #[test]
    fn test_u256_zero_value() {
        let zero = U256::zero();
        let encoded = zero.to_abi().to_vec();
        assert_eq!(encoded, vec![0u8; 32]);
    }

    #[test]
    fn test_h256_type_constants() {
        assert_eq!(H256::BASIC_TYPE, <[u8; 32]>::BASIC_TYPE);
        assert_eq!(H256::STATIC_LENGTH, <[u8; 32]>::STATIC_LENGTH);
    }

    #[test]
    fn test_h256_from_abi_valid() {
        let input = [42u8; 32];
        let h256 = H256::from_abi(&input).unwrap();
        assert_eq!(h256.0, input);
    }

    #[test]
    fn test_h256_to_packed_abi() {
        let h256 = H256([0xBB; 32]);
        let packed_bytes = h256.to_packed_abi();
        assert_eq!(packed_bytes.to_vec(), &[0xBB; 32]);
    }

    #[test]
    fn test_u8_bits() {
        assert_eq!(U8::BITS, 8);
    }

    #[test]
    fn test_u8_to_be_bytes() {
        let val = U8::from_be_bytes([123]);
        assert_eq!(val.to_be_bytes(), [123]);
    }

    #[test]
    fn test_u8_from_be_bytes() {
        let u = U8::from_be_bytes([255]);
        assert_eq!(u.to_be_bytes(), [255]);
    }

    #[test]
    fn test_u8_eq() {
        let a = U8::from_be_bytes([100]);
        let b = U8::from_be_bytes([100]);
        let c = U8::from_be_bytes([200]);
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn test_u8_boundaries() {
        let min = U8::from_be_bytes([0]);
        let max = U8::from_be_bytes([255]);
        assert_eq!(min.to_be_bytes(), [0]);
        assert_eq!(max.to_be_bytes(), [255]);
    }

    #[test]
    fn test_u8_byte_order_consistency() {
        let input = [128];
        let u = U8::from_be_bytes(input);
        assert_eq!(u.to_be_bytes(), input);
    }

    // -------------------------------------------------------------------
    // Pin-down tests for the non-strict `uintN` decoding behavior in
    // `impl_abi_variable_for_primitive!`.
    //
    // These tests intentionally lock in the *current* "silently take the
    // low BYTES bytes" semantics. The behavior is consensus-critical:
    // changing it would alter how historical calldata to built-in
    // contracts decodes and would require a Spec-gated transition (CIP).
    //
    // If a future change "fixes" `from_abi` to reject non-zero high bytes
    // without a hard-fork gate, these tests should fail and force the
    // change to go through the proper consensus-upgrade path. See the
    // doc-comment on `from_abi` above for the full rationale.
    // -------------------------------------------------------------------

    /// Build a 32-byte ABI word whose low `n` bytes hold the big-endian
    /// representation of `low` and whose high `32 - n` bytes are filled
    /// with `high_fill`.
    fn make_word_with_high_fill(low: &[u8], high_fill: u8) -> [u8; 32] {
        assert!(low.len() <= 32, "low slice must fit in a 32-byte ABI word");
        let mut word = [high_fill; 32];
        let start = 32 - low.len();
        word[start..].copy_from_slice(low);
        word
    }

    #[test]
    fn test_u8_truncates_high_bytes() {
        // The local `U8` newtype also flows through the
        // `impl_abi_variable_for_primitive!` macro and therefore inherits
        // the same low-byte truncation. Lock this in so a future
        // "fix" cannot quietly tighten U8 decoding.
        let word = make_word_with_high_fill(&[0xAB], 0xFF);
        let decoded = U8::from_abi(&word).unwrap();
        assert_eq!(decoded.to_be_bytes(), [0xAB]);
    }

    #[test]
    fn test_u16_truncates_high_bytes() {
        // Low 2 bytes encode 0x1234; the remaining 30 high bytes are
        // 0xFF. A Solidity uint16 dispatcher would revert; we instead
        // silently keep only the low 2 bytes.
        let word = make_word_with_high_fill(&0x1234u16.to_be_bytes(), 0xFF);
        let decoded = u16::from_abi(&word).unwrap();
        assert_eq!(decoded, 0x1234u16);
    }

    #[test]
    fn test_u32_truncates_high_bytes() {
        let word = make_word_with_high_fill(&0xDEADBEEFu32.to_be_bytes(), 0xAA);
        let decoded = u32::from_abi(&word).unwrap();
        assert_eq!(decoded, 0xDEADBEEFu32);
    }

    #[test]
    fn test_u64_truncates_high_bytes() {
        let word = make_word_with_high_fill(
            &0x0123_4567_89AB_CDEFu64.to_be_bytes(),
            0x01,
        );
        let decoded = u64::from_abi(&word).unwrap();
        assert_eq!(decoded, 0x0123_4567_89AB_CDEFu64);
    }

    #[test]
    fn test_u128_truncates_high_bytes() {
        let low: u128 = 0x0011_2233_4455_6677_8899_AABB_CCDD_EEFFu128;
        let word = make_word_with_high_fill(&low.to_be_bytes(), 0x77);
        let decoded = u128::from_abi(&word).unwrap();
        assert_eq!(decoded, low);
    }

    #[test]
    fn test_uintn_accepts_max_low_with_dirty_high_bits() {
        // u64::MAX in the low 8 bytes plus arbitrary garbage in the
        // high 24 bytes should still decode to u64::MAX, not error.
        let word = make_word_with_high_fill(&u64::MAX.to_be_bytes(), 0x5A);
        let decoded = u64::from_abi(&word).unwrap();
        assert_eq!(decoded, u64::MAX);
    }

    #[test]
    fn test_uintn_decoding_is_non_canonical() {
        // Two distinct 32-byte words that differ only in their high
        // (ignored) bytes must decode to the same u32. This documents
        // that built-in calldata is *not* canonical at the ABI layer.
        let value: u32 = 0xCAFEBABE;
        let word_clean = make_word_with_high_fill(&value.to_be_bytes(), 0x00);
        let word_dirty = make_word_with_high_fill(&value.to_be_bytes(), 0xFF);
        assert_ne!(word_clean, word_dirty);
        assert_eq!(
            u32::from_abi(&word_clean).unwrap(),
            u32::from_abi(&word_dirty).unwrap(),
        );
    }

    #[test]
    fn test_uintn_rejects_wrong_word_length() {
        // The length check is the only validation `from_abi` performs;
        // make sure it still fires for non-32-byte inputs.
        assert!(u16::from_abi(&[0u8; 31]).is_err());
        assert!(u32::from_abi(&[0u8; 33]).is_err());
        assert!(u64::from_abi(&[]).is_err());
        assert!(u128::from_abi(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_uintn_roundtrip_zero_high_bytes() {
        // Encoding via `to_abi` always zero-pads the high bytes; the
        // round trip through `from_abi` must be the identity.
        let cases_u16: &[u16] = &[0, 1, 0x1234, u16::MAX];
        for &v in cases_u16 {
            let bytes = v.to_abi().to_vec();
            assert_eq!(bytes.len(), 32);
            assert!(bytes[..30].iter().all(|&b| b == 0));
            assert_eq!(u16::from_abi(&bytes).unwrap(), v);
        }

        let cases_u64: &[u64] = &[0, 1, 0x0123_4567_89AB_CDEF, u64::MAX];
        for &v in cases_u64 {
            let bytes = v.to_abi().to_vec();
            assert_eq!(bytes.len(), 32);
            assert!(bytes[..24].iter().all(|&b| b == 0));
            assert_eq!(u64::from_abi(&bytes).unwrap(), v);
        }
    }
}
