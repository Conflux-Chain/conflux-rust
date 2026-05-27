use cfx_types::{Address, U256, U64};
use primitives::transaction::AuthorizationListItem;
use serde::{Deserialize, Deserializer};

#[derive(
    Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize, Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The chain ID of the authorization.
    pub chain_id: U256,
    /// The address of the authorization.
    pub address: Address,
    /// The nonce for the authorization.
    pub nonce: U64,
}

#[derive(
    Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize, Clone,
)]
#[serde(rename_all = "camelCase")]
pub struct SignedAuthorization {
    /// Inner authorization.
    #[serde(flatten)]
    inner: Authorization,
    /// Signature parity value. Must be `0` or `1`.
    #[serde(deserialize_with = "parse_and_validate_y_parity")]
    pub y_parity: U64,
    /// Signature `r` value.
    pub r: U256,
    /// Signature `s` value.
    pub s: U256,
}

impl SignedAuthorization {
    /// Returns the inner authorization.
    pub const fn inner(&self) -> &Authorization { &self.inner }

    /// Returns the signature parity value.
    pub fn y_parity(&self) -> u8 { self.y_parity.as_u32() as u8 }

    /// Returns the signature `r` value.
    pub const fn r(&self) -> U256 { self.r }

    /// Returns the signature `s` value.
    pub const fn s(&self) -> U256 { self.s }
}

impl From<AuthorizationListItem> for SignedAuthorization {
    fn from(item: AuthorizationListItem) -> Self {
        Self {
            inner: Authorization {
                chain_id: item.chain_id.into(),
                address: item.address.into(),
                nonce: item.nonce.into(),
            },
            y_parity: item.y_parity.into(),
            r: item.r,
            s: item.s,
        }
    }
}

fn parse_and_validate_y_parity<'de, D>(deserializer: D) -> Result<U64, D::Error>
where D: Deserializer<'de> {
    let v = U64::deserialize(deserializer)?;
    if v.as_u64() > 1 {
        return Err(serde::de::Error::custom(format!(
            "invalid yParity: expected 0 or 1, got {}",
            v
        )));
    }
    Ok(v)
}

impl Into<AuthorizationListItem> for SignedAuthorization {
    fn into(self) -> AuthorizationListItem {
        AuthorizationListItem {
            chain_id: self.inner.chain_id,
            address: self.inner.address,
            nonce: self.inner.nonce.as_u64(),
            y_parity: self.y_parity(),
            r: self.r,
            s: self.s,
        }
    }
}
