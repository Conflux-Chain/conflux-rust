use diem_types::transaction::SignedTransaction;

use diem_types::transaction::{GovernanceRole, VMValidatorResult};
use move_core_types::vm_status::DiscardedVMStatus;

pub struct TransactionValidator {}

impl TransactionValidator {
    pub fn new() -> Self { Self {} }

    pub fn validate_transaction(
        &self, tx: SignedTransaction,
    ) -> Option<VMValidatorResult> {
        // check signature
        if tx.check_signature().is_err() {
            return Some(VMValidatorResult::new(
                Some(DiscardedVMStatus::INVALID_SIGNATURE),
                0,
                GovernanceRole::Validator,
            ));
        }

        Some(VMValidatorResult::new(None, 0, GovernanceRole::Validator))
    }
}
