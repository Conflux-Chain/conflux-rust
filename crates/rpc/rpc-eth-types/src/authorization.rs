use alloy_eips::eip7702::{
    Authorization as EthAuthorization,
    SignedAuthorization as EthSignedAuthorization,
};
use alloy_primitives_wrapper::{WAddress, WU256};
use primitives::transaction::AuthorizationListItem;

#[derive(Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedAuthorization(pub EthSignedAuthorization);

impl From<AuthorizationListItem> for SignedAuthorization {
    fn from(item: AuthorizationListItem) -> Self {
        let auth = EthAuthorization {
            chain_id: WU256::from(item.chain_id).into(),
            address: WAddress::from(item.address).into(),
            nonce: item.nonce,
        };
        Self(EthSignedAuthorization::new_unchecked(
            auth,
            item.y_parity,
            WU256::from(item.r).into(),
            WU256::from(item.s).into(),
        ))
    }
}

impl Into<AuthorizationListItem> for SignedAuthorization {
    fn into(self) -> AuthorizationListItem {
        let inner = self.0.inner();
        AuthorizationListItem {
            chain_id: WU256::from(inner.chain_id).into(),
            address: WAddress::from(inner.address).into(),
            nonce: inner.nonce,
            y_parity: self.0.y_parity(),
            r: WU256::from(self.0.r()).into(),
            s: WU256::from(self.0.s()).into(),
        }
    }
}

impl Into<EthSignedAuthorization> for SignedAuthorization {
    fn into(self) -> EthSignedAuthorization { self.0 }
}
