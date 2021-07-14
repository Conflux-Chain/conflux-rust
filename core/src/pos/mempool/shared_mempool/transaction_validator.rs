use diem_types::transaction::SignedTransaction;

use diem_types::transaction::{GovernanceRole, VMValidatorResult};

pub struct TransactionValidator {}

impl TransactionValidator {
    pub fn new() -> Self { Self {} }

    pub fn validate_transaction(
        &self, _tx: SignedTransaction,
    ) -> Option<VMValidatorResult> {
        Some(VMValidatorResult::new(None, 0, GovernanceRole::Validator))
    }
}
