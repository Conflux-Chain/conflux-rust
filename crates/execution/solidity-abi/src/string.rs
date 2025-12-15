use super::{bytes::Bytes, ABIDecodeError, ABIVariable, LinkedBytes};
use std::str::from_utf8;

impl ABIVariable for String {
    const BASIC_TYPE: bool = false;
    const STATIC_LENGTH: Option<usize> = None;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let byte_array = Bytes::from_abi(data)?;
        from_utf8(&byte_array)
            .and_then(|s| Ok(s.to_string()))
            .map_err(|_| ABIDecodeError("Utf8 decoding error"))
    }

    fn to_abi(&self) -> LinkedBytes { self.as_bytes().to_vec().to_abi() }

    fn to_packed_abi(&self) -> LinkedBytes {
        self.as_bytes().to_vec().to_packed_abi()
    }
}
