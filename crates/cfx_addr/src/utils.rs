use crate::types::DecodingError;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// The polymod function is used to calculate the checksum of the address.
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

/// The checksum calculation includes the lower 5 bits of each character of the
/// prefix.
/// - e.g. "bit..." becomes 2,9,20,...
// Expand the address prefix for the checksum operation.
pub fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut ret: Vec<u8> = prefix.chars().map(|c| (c as u8) & 0x1f).collect();
    ret.push(0);
    ret
}

// This method assume that data is valid string of inbits.
// When pad is true, any remaining bits are padded and encoded into a new byte;
// when pad is false, any remaining bits are checked to be zero and discarded.
pub fn convert_bits(
    data: &[u8], inbits: u8, outbits: u8, pad: bool,
) -> Result<Vec<u8>, DecodingError> {
    assert!(inbits <= 8 && outbits <= 8);
    let num_bytes = (data.len() * inbits as usize + outbits as usize - 1)
        / outbits as usize;
    let mut ret = Vec::with_capacity(num_bytes);
    let mut acc: u16 = 0; // accumulator of bits
    let mut num: u8 = 0; // num bits in acc
    let groupmask = (1 << outbits) - 1;
    for d in data.iter() {
        // We push each input chunk into a 16-bit accumulator
        acc = (acc << inbits) | u16::from(*d);
        num += inbits;
        // Then we extract all the output groups we can
        while num >= outbits {
            // Store only the highest outbits.
            ret.push((acc >> (num - outbits)) as u8);
            // Clear the highest outbits.
            acc &= !(groupmask << (num - outbits));
            num -= outbits;
        }
    }
    if pad {
        // If there's some bits left, pad and add it
        if num > 0 {
            ret.push((acc << (outbits - num)) as u8);
        }
    } else {
        // FIXME: add unit tests for it.
        // If there's some bits left, figure out if we need to remove padding
        // and add it
        let padding = ((data.len() * inbits as usize) % outbits as usize) as u8;
        if num >= inbits || acc != 0 {
            return Err(DecodingError::InvalidPadding {
                from_bits: inbits,
                padding_bits: padding,
                padding: acc,
            });
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_prefix() {
        assert_eq!(expand_prefix("cfx"), vec![0x03, 0x06, 0x18, 0x00]);

        assert_eq!(
            expand_prefix("cfxtest"),
            vec![0x03, 0x06, 0x18, 0x14, 0x05, 0x13, 0x14, 0x00]
        );

        assert_eq!(
            expand_prefix("net17"),
            vec![0x0e, 0x05, 0x14, 0x11, 0x17, 0x00]
        );
    }

    #[test]
    fn test_convert_bits() {
        // 00000000 --> 0, 0, 0, 0, 0, 0, 0, 0
        assert_eq!(convert_bits(&[0], 8, 1, false), Ok(vec![0; 8]));

        // 00000000 --> 000, 000, 00_
        assert_eq!(convert_bits(&[0], 8, 3, false), Ok(vec![0, 0])); // 00_ is dropped
        assert_eq!(convert_bits(&[0], 8, 3, true), Ok(vec![0, 0, 0])); // 00_ becomes 000

        // 00000001 --> 000, 000, 01_
        assert!(convert_bits(&[1], 8, 3, false).is_err()); // 01_ != 0 (ignored incomplete chunk must be 0)
        assert_eq!(convert_bits(&[1], 8, 3, true), Ok(vec![0, 0, 2])); // 01_ becomes 010

        // 00000001 --> 0000000, 1______
        assert_eq!(convert_bits(&[1], 8, 7, true), Ok(vec![0, 64])); // 1______ becomes 1000000

        // 0, 0, 0, 0, 0, 0, 0, 0 --> 00000000
        assert_eq!(convert_bits(&[0; 8], 1, 8, false), Ok(vec![0]));

        // 000, 000, 010 -> 00000001, 0_______
        assert_eq!(convert_bits(&[0, 0, 2], 3, 8, false), Ok(vec![1])); // 0_______ is dropped
        assert_eq!(convert_bits(&[0, 0, 2], 3, 8, true), Ok(vec![1, 0])); // 0_______ becomes 00000000

        // 000, 000, 011 -> 00000001, 1_______
        assert!(convert_bits(&[0, 0, 3], 3, 8, false).is_err()); // 1_______ != 0 (ignored incomplete chunk must be 0)

        // 00000000, 00000001, 00000010, 00000011, 00000100 -->
        // 00000, 00000, 00000, 10000, 00100, 00000, 11000, 00100
        assert_eq!(
            convert_bits(&[0, 1, 2, 3, 4], 8, 5, false),
            Ok(vec![0, 0, 0, 16, 4, 0, 24, 4])
        );

        // 00000000, 00000001, 00000010 -->
        // 00000, 00000, 00000, 10000, 0010_
        assert!(convert_bits(&[0, 1, 2], 8, 5, false).is_err()); // 0010_ != 0 (ignored incomplete chunk must be 0)

        assert_eq!(
            convert_bits(&[0, 1, 2], 8, 5, true),
            Ok(vec![0, 0, 0, 16, 4])
        ); // 0010_ becomes 00100

        // 00000, 00000, 00000, 10000, 00100, 00000, 11000, 00100 -->
        // 00000000, 00000001, 00000010, 00000011, 00000100
        assert_eq!(
            convert_bits(&[0, 0, 0, 16, 4, 0, 24, 4], 5, 8, false),
            Ok(vec![0, 1, 2, 3, 4])
        );

        // 00000, 00000, 00000, 10000, 00100 -->
        // 00000000, 00000001, 00000010, 0_______
        assert_eq!(
            convert_bits(&[0, 0, 0, 16, 4], 5, 8, false),
            Ok(vec![0, 1, 2])
        ); // 0_______ is dropped

        assert_eq!(
            convert_bits(&[0, 0, 0, 16, 4], 5, 8, true),
            Ok(vec![0, 1, 2, 0])
        ); // 0_______ becomes 00000000
    }
}
