use cfx_types::{Address, U256};

/// An unsigned EIP-7702 authorization.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Authorization {
    /// The chain ID of the authorization.
    pub chain_id: U256,
    /// The address of the authorization.
    pub address: Address,
    /// The nonce for the authorization.
    #[cfg_attr(feature = "serde", serde(with = "quantity"))]
    pub nonce: u64,
}

/// A signed EIP-7702 authorization.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignedAuthorization {
    /// Inner authorization.
    #[cfg_attr(feature = "serde", serde(flatten))]
    inner: Authorization,
    /// Signature parity value. We allow any [`U8`] here, however, the only
    /// valid values are `0` and `1` and anything else will result in error
    /// during recovery.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "yParity", alias = "v", with = "quantity")
    )]
    y_parity: u64,
    /// Signature `r` value.
    r: U256,
    /// Signature `s` value.
    s: U256,
}

impl SignedAuthorization {
    /// Returns the inner [`Authorization`].
    pub const fn strip_signature(self) -> Authorization { self.inner }

    /// Returns the inner [`Authorization`].
    pub const fn inner(&self) -> &Authorization { &self.inner }

    /// Returns the signature parity value.
    pub fn y_parity(&self) -> u8 { self.y_parity as u8 }

    /// Returns the signature `r` value.
    pub const fn r(&self) -> U256 { self.r }

    /// Returns the signature `s` value.
    pub const fn s(&self) -> U256 { self.s }
}

#[cfg(feature = "serde")]
mod quantity {
    use cfx_types::U64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a primitive number as a "quantity" hex string.
    pub(crate) fn serialize<S>(
        value: &u64, serializer: S,
    ) -> Result<S::Ok, S::Error>
    where S: Serializer {
        U64::from(*value).serialize(serializer)
    }

    /// Deserializes a primitive number from a "quantity" hex string.
    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<u64, D::Error>
    where D: Deserializer<'de> {
        U64::deserialize(deserializer).map(|value| value.as_u64())
    }
}
