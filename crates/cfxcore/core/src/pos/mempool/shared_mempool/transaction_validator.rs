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
        let authenticator = tx.authenticator();
        let auth_pk = match &authenticator {
            TransactionAuthenticator::BLS { public_key, .. } => public_key,
            _ => return Some(DiscardedVMStatus::INVALID_SIGNATURE),
        };

        let sender = tx.sender();
        let result = match tx.payload() {
            TransactionPayload::Election(election_payload) => pos_state
                .validate_election_simple(&sender, auth_pk, election_payload),
            TransactionPayload::PivotDecision(pivot_decision) => pos_state
                .validate_pivot_decision_simple(
                    &sender,
                    auth_pk,
                    pivot_decision,
                ),
            TransactionPayload::Dispute(_) => {
                pos_state.validate_dispute_simple(&sender, auth_pk)
            }
            TransactionPayload::Register(_)
            | TransactionPayload::Retire(_)
            | TransactionPayload::UpdateVotingPower(_) => {
                return Some(
                    DiscardedVMStatus::PAYLOAD_NOT_ALLOWED_VIA_MEMPOOL,
                );
            }
            _ => None,
        };
        if result.is_some() {
            return result;
        }

        if tx.verify_signature().is_err() {
            return Some(DiscardedVMStatus::INVALID_SIGNATURE);
        }

        None
    }
}
