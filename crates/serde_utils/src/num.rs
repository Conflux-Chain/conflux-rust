use cfx_types::{U256, U64};
use core::str::FromStr;
use serde::{de, Deserialize, Deserializer};
use std::fmt;

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
pub fn from_int_or_hex_to_u256<'de, D>(
    deserializer: D,
) -> Result<U256, D::Error>
where D: Deserializer<'de> {
    NumberOrHexU256::deserialize(deserializer)?.try_into_u256()
}

/// Deserializes the input into an `Option<U256>`, using [`from_int_or_hex`] to
/// deserialize the inner value.
pub fn from_int_or_hex_to_u256_opt<'de, D>(
    deserializer: D,
) -> Result<Option<U256>, D::Error>
where D: Deserializer<'de> {
    match Option::<NumberOrHexU256>::deserialize(deserializer)? {
        Some(val) => val.try_into_u256().map(Some),
        None => Ok(None),
    }
}

/// An enum that represents either a [serde_json::Number] integer, or a hex
/// [U64].
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NumberOrHexU64 {
    /// An integer
    Int(serde_json::Number),
    /// A hex U64
    Hex(U64),
}

impl NumberOrHexU64 {
    /// Tries to convert this into a [U64]].
    pub fn try_into_u64<E: de::Error>(self) -> Result<U64, E> {
        match self {
            NumberOrHexU64::Int(num) => {
                U64::from_str(num.to_string().as_str()).map_err(E::custom)
            }
            NumberOrHexU64::Hex(val) => Ok(val),
        }
    }
}

/// Deserializes the input into a U64, accepting both 0x-prefixed hex and
/// decimal strings with arbitrary precision, defined by serde_json's
/// [`Number`](serde_json::Number).
pub fn from_int_or_hex_to_u64<'de, D>(
    deserializer: D,
) -> Result<U64, D::Error>
where D: Deserializer<'de> {
    NumberOrHexU64::deserialize(deserializer)?.try_into_u64()
}

/// Deserializes the input into an `Option<U64>`, using
/// [`from_int_or_hex_to_u64`] to deserialize the inner value.
pub fn from_int_or_hex_to_u64_opt<'de, D>(
    deserializer: D,
) -> Result<Option<U64>, D::Error>
where D: Deserializer<'de> {
    match Option::<NumberOrHexU64>::deserialize(deserializer)? {
        Some(val) => val.try_into_u64().map(Some),
        None => Ok(None),
    }
}

pub fn deserialize_u64_from_num_or_hex<'de, D>(
    deserializer: D,
) -> Result<u64, D::Error>
where D: Deserializer<'de> {
    struct U64OrHexVisitor;

    impl<'de> serde::de::Visitor<'de> for U64OrHexVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter
                .write_str("a u64 integer or a hex string representing a u64")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E> { Ok(value) }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where E: serde::de::Error {
            if let Some(stripped) = value.strip_prefix("0x") {
                u64::from_str_radix(stripped, 16).map_err(E::custom)
            } else {
                Err(E::custom("expected hex string to start with '0x'"))
            }
        }
    }

    deserializer.deserialize_any(U64OrHexVisitor)
}
