pub mod num;
pub mod rlp_compat;
pub use num::*;
pub use rlp_compat::rlp_decode_bool_compat;

use serde::Serializer;

/// Serialize a byte vec as a hex string _without_ the "0x" prefix.
///
/// This behaves the same as [`hex::encode`](alloy_primitives::hex::encode).
pub fn serialize_hex_string_no_prefix<S, T>(
    x: T, s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    s.serialize_str(&alloy_primitives::hex::encode(x.as_ref()))
}
