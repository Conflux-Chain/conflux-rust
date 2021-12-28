use diem_types::{
    term_state::PosState,
    transaction::{
        authenticator::TransactionAuthenticator, GovernanceRole,
        SignedTransaction, TransactionPayload, VMValidatorResult,
    },
};
use move_core_types::vm_status::DiscardedVMStatus;
use std::sync::Arc;

pub struct TransactionValidator {}

impl TransactionValidator {
    pub fn new() -> Self { Self {} }

    // TODO: `score` and `governance_role` in `VMValidatorResult` are not
    // needed now.
    pub fn validate_transaction(
        &self, tx: &SignedTransaction, pos_state: Arc<PosState>,
    ) -> Option<VMValidatorResult> {
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
            return Some(VMValidatorResult::new(
                result,
                0,
                GovernanceRole::Validator,
            ));
        }

        match tx.authenticator() {
            TransactionAuthenticator::BLS { .. } => {}
            _ => {
                return Some(VMValidatorResult::new(
                    Some(DiscardedVMStatus::INVALID_SIGNATURE),
                    0,
                    GovernanceRole::Validator,
                ));
            }
        }

        // check signature
        if tx.clone().check_signature().is_err() {
            return Some(VMValidatorResult::new(
                Some(DiscardedVMStatus::INVALID_SIGNATURE),
                0,
                GovernanceRole::Validator,
            ));
        }

        Some(VMValidatorResult::new(result, 0, GovernanceRole::Validator))
    }
}
