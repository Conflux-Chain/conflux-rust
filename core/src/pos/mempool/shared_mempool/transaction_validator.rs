use diem_types::{
    term_state::PosState,
    transaction::{
        GovernanceRole, SignedTransaction, TransactionPayload,
        VMValidatorResult,
    },
};
use move_core_types::vm_status::DiscardedVMStatus;
use std::sync::Arc;

pub struct TransactionValidator {}

impl TransactionValidator {
    pub fn new() -> Self { Self {} }

    pub fn validate_transaction(
        &self, tx: &SignedTransaction, pos_state: Arc<PosState>,
    ) -> Option<VMValidatorResult> {
        // check signature
        if tx.clone().check_signature().is_err() {
            return Some(VMValidatorResult::new(
                Some(DiscardedVMStatus::INVALID_SIGNATURE),
                0,
                GovernanceRole::Validator,
            ));
        }

        let result = match tx.payload() {
            TransactionPayload::Election(election_payload) => {
                pos_state.validate_election_simple(election_payload)
            }
            TransactionPayload::Retire(retire_payload) => {
                pos_state.validate_retire_simple(retire_payload)
            }
            TransactionPayload::PivotDecision(pivot_decision) => {
                pos_state.validate_pivot_decision_simple(pivot_decision)
            }
            _ => None,
        };

        Some(VMValidatorResult::new(result, 0, GovernanceRole::Validator))
    }
}
