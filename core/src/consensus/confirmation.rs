use cfx_types::H256;

pub trait ConfirmationTrait {
    fn confirmation_risk_by_hash(&self, hash: H256) -> Option<f64>;
}
