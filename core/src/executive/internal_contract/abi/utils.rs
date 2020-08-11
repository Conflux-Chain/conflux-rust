use super::ABIDecodeError;
use cfx_types::U256;
use std::slice::Iter;

#[inline]
pub fn abi_require(
    claim: bool, desc: &'static str,
) -> Result<(), ABIDecodeError> {
    if !claim {
        Err(ABIDecodeError(desc))
    } else {
        Ok(())
    }
}

#[inline]
pub fn to_big_endian(x: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    U256::from(x).to_big_endian(&mut bytes);
    bytes
}

#[inline]
pub fn pull_slice<'a>(
    iter: &mut Iter<'a, u8>, n: usize,
) -> Result<&'a [u8], ABIDecodeError> {
    abi_require(iter.len() >= n, "Invalid call data length")?;

    let slice = iter.as_slice();
    let result = &slice[0..n];
    *iter = slice[n..].iter();
    Ok(result)
}
