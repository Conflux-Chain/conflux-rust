use diem_types::{
    term_state::PosState,
    transaction::{
        authenticator::TransactionAuthenticator, SignedTransaction,
        TransactionPayload,
    },
};
use move_core_types::vm_status::DiscardedVMStatus;
use std::sync::Arc;

pub struct TransactionValidator {}

impl TransactionValidator {
    pub fn new() -> Self { Self {} }

    /// Returns `None` if the transaction is accepted, or a
    /// `DiscardedVMStatus` describing why it should be rejected.
    pub fn validate_transaction(
        &self, tx: &SignedTransaction, pos_state: Arc<PosState>,
    ) -> Option<DiscardedVMStatus> {
        // This check is cheaper than signature verification, so we do not
        // need to verify signatures for old transactions.
        let result = match tx.payload() {
            TransactionPayload::Election(election_payload) => {
                pos_state.validate_election_simple(election_payload)
            }
            TransactionPayload::PivotDecision(pivot_decision) => {
                pos_state.validate_pivot_decision_simple(pivot_decision)
            }
            _ => None,
        };
        if result.is_some() {
            return result;
        }

        match tx.authenticator() {
            TransactionAuthenticator::BLS { .. } => {}
            _ => return Some(DiscardedVMStatus::INVALID_SIGNATURE),
        }

        if tx.clone().check_signature().is_err() {
            return Some(DiscardedVMStatus::INVALID_SIGNATURE);
        }

        if tx.expiration_timestamp_secs() != u64::MAX {
            return Some(DiscardedVMStatus::INVALID_EXPIRATION_TIME);
        }

        None
    }
}
