use cfx_types::{Address, U256, U64};
use primitives::transaction::AuthorizationListItem;

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
    /// Signature parity value. We allow any [`U64`] here, however, the only
    /// valid values are `0` and `1` and anything else will result in error
    /// during recovery.
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

impl Into<AuthorizationListItem> for SignedAuthorization {
    fn into(self) -> AuthorizationListItem {
        AuthorizationListItem {
            chain_id: self.inner.chain_id.as_u64(),
            address: self.inner.address,
            nonce: self.inner.nonce.as_u64(),
            y_parity: self.y_parity(),
            r: self.r,
            s: self.s,
        }
    }
}
