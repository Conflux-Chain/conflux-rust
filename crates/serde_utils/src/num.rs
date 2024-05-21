use cfx_types::U256;
use core::str::FromStr;
use serde::{de, Deserialize, Deserializer};

/// An enum that represents either a [serde_json::Number] integer, or a hex
/// [U256].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrHexU256 {
    /// An integer
    Int(serde_json::Number),
    /// A hex U256
    Hex(U256),
}

impl NumberOrHexU256 {
    /// Tries to convert this into a [U256]].
    pub fn try_into_u256<E: de::Error>(self) -> Result<U256, E> {
        match self {
            NumberOrHexU256::Int(num) => {
                U256::from_str(num.to_string().as_str()).map_err(E::custom)
            }
            NumberOrHexU256::Hex(val) => Ok(val),
        }
    }
}

/// Deserializes the input into a U256, accepting both 0x-prefixed hex and
/// decimal strings with arbitrary precision, defined by serde_json's
/// [`Number`](serde_json::Number).
pub fn from_int_or_hex<'de, D>(deserializer: D) -> Result<U256, D::Error>
where D: Deserializer<'de> {
    NumberOrHexU256::deserialize(deserializer)?.try_into_u256()
}

/// Deserializes the input into an `Option<U256>`, using [`from_int_or_hex`] to
/// deserialize the inner value.
pub fn from_int_or_hex_opt<'de, D>(
    deserializer: D,
) -> Result<Option<U256>, D::Error>
where D: Deserializer<'de> {
    match Option::<NumberOrHexU256>::deserialize(deserializer)? {
        Some(val) => val.try_into_u256().map(Some),
        None => Ok(None),
    }
}
