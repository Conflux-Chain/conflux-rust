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
        // Authenticator must be BLS — the per-type checks below assume a
        // BLS public key is available to bind against `node_map`. Doing
        // this first also avoids paying for payload lookups on
        // malformed inputs. `tx.authenticator()` returns by value (it
        // clones internally), so hold onto the binding for the lifetime
        // of `auth_pk`.
        let authenticator = tx.authenticator();
        let auth_pk = match &authenticator {
            TransactionAuthenticator::BLS { public_key, .. } => public_key,
            _ => return Some(DiscardedVMStatus::INVALID_SIGNATURE),
        };

        // Reject payload types that never legitimately enter via mempool
        // gossip. Register/Retire/UpdateVotingPower are proposer-built
        // from PoW staking events (see
        // `proposal_generator::generate_proposal` →
        // `RawTransaction::from_staking_event`) and pushed straight into
        // the block payload, so any copy seen on the gossip path is
        // adversarial. Admitting them would let a peer seed the
        // mempool with non-matching staking events that a proposer
        // could then pull into a doomed block.
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
