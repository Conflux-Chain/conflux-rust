use consensus_types::{block::Block, block_data::BlockType, vote::Vote};
use diem_crypto::hash::CryptoHash;
use diem_logger::{error as diem_error, prelude::*};
use diem_state_view::StateView;
use diem_types::{
    account_address::{from_consensus_public_key, AccountAddress},
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    on_chain_config::new_epoch_event_key,
    term_state::pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG},
    transaction::{
        authenticator::TransactionAuthenticator, ConflictSignature,
        DisputePayload, ElectionPayload, RegisterPayload, RetirePayload,
        SignatureCheckedTransaction, SignedTransaction, Transaction,
        TransactionOutput, TransactionPayload, TransactionStatus,
        UpdateVotingPowerPayload,
    },
    validator_verifier::ValidatorVerifier,
    vm_status::{KeptVMStatus, StatusCode, VMStatus},
};

/// A VM for Conflux PoS chain.
pub struct PosVM;

impl PosVM {
    /// Executes a block of transactions and returns output for each one of
    /// them.
    pub fn execute_block(
        transactions: Vec<Transaction>, state_view: &dyn StateView,
        catch_up_mode: bool,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        let mut vm_outputs = Vec::new();
        for transaction in transactions {
            let output = match transaction {
                Transaction::BlockMetadata(_) => {
                    Self::process_block_metadata(state_view)?
                }
                Transaction::UserTransaction(trans) => {
                    let tx = Self::check_signature_for_user_tx(trans)?;
                    let spec = Spec { catch_up_mode };
                    Self::process_user_transaction(state_view, &tx, &spec)?
                }
                Transaction::GenesisTransaction(events) => {
                    Self::process_genesis_transaction(events)?
                }
            };
            vm_outputs.push(output);
        }

        Ok(vm_outputs)
    }
}

impl PosVM {
    fn process_block_metadata(
        state_view: &dyn StateView,
    ) -> Result<TransactionOutput, VMStatus> {
        let mut events = state_view.pos_state().get_unlock_events();
        diem_debug!("get_unlock_events: {}", events.len());

        let next_view = state_view.pos_state().current_view() + 1;
        let (term, view_in_term) = POS_STATE_CONFIG.get_term_view(next_view);

        // TODO(lpl): Simplify.
        if view_in_term == 0 {
            let (validator_verifier, vrf_seed) =
                state_view.pos_state().get_committee_at(term).map_err(|e| {
                    diem_warn!("get_new_committee error: {:?}", e);
                    VMStatus::Error(StatusCode::CFX_INVALID_TX)
                })?;
            let epoch = term + 1;
            let validator_bytes = bcs::to_bytes(&EpochState::new(
                epoch,
                validator_verifier,
                vrf_seed,
            ))
            .unwrap();
            let contract_event =
                ContractEvent::new(new_epoch_event_key(), validator_bytes);
            events.push(contract_event);
        }
        Ok(Self::gen_output(events))
    }

    fn check_signature_for_user_tx(
        trans: SignedTransaction,
    ) -> Result<SignatureCheckedTransaction, VMStatus> {
        // TODO(lpl): Parallel verification.
        trans.check_signature().map_err(|e| {
            diem_trace!("invalid transactions signature: e={:?}", e);
            VMStatus::Error(StatusCode::INVALID_SIGNATURE)
        })
    }

    fn process_user_transaction(
        state_view: &dyn StateView, tx: &SignatureCheckedTransaction,
        spec: &Spec,
    ) -> Result<TransactionOutput, VMStatus> {
        let events = match tx.payload() {
            TransactionPayload::Election(election_payload) => {
                election_payload.execute(state_view, tx, spec)?
            }
            TransactionPayload::Retire(retire_payload) => {
                retire_payload.execute(state_view, tx, spec)?
            }
            TransactionPayload::PivotDecision(pivot_decision) => {
                pivot_decision.execute(state_view, tx, spec)?
            }
            TransactionPayload::Register(register) => {
                register.execute(state_view, tx, spec)?
            }
            TransactionPayload::UpdateVotingPower(update) => {
                update.execute(state_view, tx, spec)?
            }
            TransactionPayload::Dispute(dispute) => {
                dispute.execute(state_view, tx, spec)?
            }
            _ => return Err(VMStatus::Error(StatusCode::CFX_UNEXPECTED_TX)),
        };

        Ok(Self::gen_output(events))
    }

    fn process_genesis_transaction(
        events: Vec<ContractEvent>,
    ) -> Result<TransactionOutput, VMStatus> {
        Ok(Self::gen_output(events))
    }

    fn gen_output(events: Vec<ContractEvent>) -> TransactionOutput {
        let status = TransactionStatus::Keep(KeptVMStatus::Executed);
        TransactionOutput::new(events, 0, status)
    }
}

pub struct Spec {
    pub catch_up_mode: bool,
}

pub trait ExecutableBuiltinTx {
    fn execute(
        &self, state_view: &dyn StateView, tx: &SignatureCheckedTransaction,
        spec: &Spec,
    ) -> Result<Vec<ContractEvent>, VMStatus>;
}

impl ExecutableBuiltinTx for ElectionPayload {
    fn execute(
        &self, state_view: &dyn StateView, _tx: &SignatureCheckedTransaction,
        spec: &Spec,
    ) -> Result<Vec<ContractEvent>, VMStatus> {
        if !spec.catch_up_mode {
            state_view
                .pos_state()
                .validate_election(self)
                .map_err(|e| {
                    diem_error!("election tx error: {:?}", e);
                    VMStatus::Error(StatusCode::CFX_INVALID_TX)
                })?;
        }
        Ok(vec![self.to_event()])
    }
}

impl ExecutableBuiltinTx for PivotBlockDecision {
    fn execute(
        &self, state_view: &dyn StateView, tx: &SignatureCheckedTransaction,
        spec: &Spec,
    ) -> Result<Vec<ContractEvent>, VMStatus> {
        if !spec.catch_up_mode {
            let authenticator = tx.authenticator();
            let signature = match authenticator {
                TransactionAuthenticator::MultiBLS { signature } => {
                    Ok(signature)
                }
                _ => Err(VMStatus::Error(StatusCode::CFX_INVALID_TX)),
            }?;
            state_view
                .pos_state()
                .validate_pivot_decision(self, signature)
                .map_err(|e| {
                    diem_error!("pivot decision tx error: {:?}", e);
                    VMStatus::Error(StatusCode::CFX_INVALID_TX)
                })?;
        }
        Ok(vec![self.to_event()])
    }
}

impl ExecutableBuiltinTx for DisputePayload {
    fn execute(
        &self, state_view: &dyn StateView, _tx: &SignatureCheckedTransaction,
        _spec: &Spec,
    ) -> Result<Vec<ContractEvent>, VMStatus> {
        state_view.pos_state().validate_dispute(self).map_err(|e| {
            diem_error!("dispute tx error: {:?}", e);
            VMStatus::Error(StatusCode::CFX_INVALID_TX)
        })?;
        let view = state_view.pos_state().current_view();
        if !verify_dispute(self, view) {
            return Err(VMStatus::Error(StatusCode::CFX_INVALID_TX));
        }
        Ok(vec![self.to_event()])
    }
}

macro_rules! impl_builtin_tx_by_gen_events {
    ( $($name:ident),*  ) => {
        $(impl ExecutableBuiltinTx for $name {
            fn execute(&self, _state_view: &dyn StateView,_tx: &SignatureCheckedTransaction,  _spec: &Spec) -> Result<Vec<ContractEvent>, VMStatus> {
                Ok(vec![self.to_event()])
            }
        })*
    }
}

// Transactions which just generate events without other process
impl_builtin_tx_by_gen_events!(
    RegisterPayload,
    RetirePayload,
    UpdateVotingPowerPayload
);

/// Verify the block is a `Proposal` signed by `address`. The embedded QC is
/// not checked: its committee signers are unknown to the single-target dispute
/// verifier.
fn verify_dispute_proposal(
    block: &Block, address: AccountAddress, verifier: &ValidatorVerifier,
) -> bool {
    match block.block_data().block_type() {
        BlockType::Proposal { author, .. } => {
            if *author != address {
                diem_trace!("Dispute proposal authored by another validator");
                return false;
            }
            match block.signature() {
                Some(signature) => verifier
                    .verify(*author, block.block_data(), signature)
                    .is_ok(),
                None => {
                    diem_trace!("Dispute proposal missing proposer signature");
                    false
                }
            }
        }
        _ => {
            diem_trace!("Dispute proposal is not a Proposal block");
            false
        }
    }
}

/// Return true if the dispute is valid.
/// Return false if the encoding is invalid or the provided signatures are
/// not from the same round.
pub fn verify_dispute(dispute: &DisputePayload, view: u64) -> bool {
    let computed_address =
        from_consensus_public_key(&dispute.bls_pub_key, &dispute.vrf_pub_key);
    if dispute.address != computed_address {
        diem_trace!("Incorrect address and public keys");
        return false;
    }
    let enforce_conflict = POS_STATE_CONFIG.enforce_dispute_conflict(view);
    match &dispute.conflicting_votes {
        ConflictSignature::Proposal((proposal_byte1, proposal_byte2)) => {
            let proposal1: Block =
                match bcs::from_bytes(proposal_byte1.as_slice()) {
                    Ok(proposal) => proposal,
                    Err(e) => {
                        diem_trace!("1st proposal encoding error: {:?}", e);
                        return false;
                    }
                };
            let proposal2: Block =
                match bcs::from_bytes(proposal_byte2.as_slice()) {
                    Ok(proposal) => proposal,
                    Err(e) => {
                        diem_trace!("2nd proposal encoding error: {:?}", e);
                        return false;
                    }
                };
            if (proposal1.block_data().epoch()
                != proposal2.block_data().epoch())
                || (proposal1.block_data().round()
                    != proposal2.block_data().round())
            {
                diem_trace!("Two proposals are from different rounds");
                return false;
            }
            let temp_verifier = ValidatorVerifier::new_single(
                dispute.address,
                dispute.bls_pub_key.clone(),
                Some(dispute.vrf_pub_key.clone()),
            );
            if enforce_conflict {
                if !verify_dispute_proposal(
                    &proposal1,
                    dispute.address,
                    &temp_verifier,
                ) || !verify_dispute_proposal(
                    &proposal2,
                    dispute.address,
                    &temp_verifier,
                ) {
                    return false;
                }
                // `id()` is the hash of `block_data` only (excludes
                // signature/vrf).
                if proposal1.id() == proposal2.id() {
                    diem_trace!("Two proposals are identical");
                    return false;
                }
            } else if proposal1.validate_signature(&temp_verifier).is_err()
                || proposal2.validate_signature(&temp_verifier).is_err()
            {
                return false;
            }
        }
        ConflictSignature::Vote((vote_byte1, vote_byte2)) => {
            let vote1: Vote = match bcs::from_bytes(vote_byte1.as_slice()) {
                Ok(vote) => vote,
                Err(e) => {
                    diem_trace!("1st vote encoding error: {:?}", e);
                    return false;
                }
            };
            let vote2: Vote = match bcs::from_bytes(vote_byte2.as_slice()) {
                Ok(vote) => vote,
                Err(e) => {
                    diem_trace!("2nd vote encoding error: {:?}", e);
                    return false;
                }
            };
            if (vote1.vote_data().proposed().epoch()
                != vote2.vote_data().proposed().epoch())
                || (vote1.vote_data().proposed().round()
                    != vote2.vote_data().proposed().round())
            {
                diem_trace!("Two votes are from different rounds");
                return false;
            }
            let temp_verifier = ValidatorVerifier::new_single(
                dispute.address,
                dispute.bls_pub_key.clone(),
                Some(dispute.vrf_pub_key.clone()),
            );
            if vote1.verify(&temp_verifier).is_err()
                || vote2.verify(&temp_verifier).is_err()
            {
                diem_trace!("dispute vote verification error: vote1_r={:?} vote2_r={:?}", vote1.verify(&temp_verifier), vote2.verify(&temp_verifier));
                return false;
            }
            // Compare `LedgerInfo` by hash, not serialized bytes: the optional
            // `timeout_signature` is not part of the `LedgerInfo`.
            if enforce_conflict
                && vote1.ledger_info().hash() == vote2.ledger_info().hash()
            {
                diem_trace!("Two votes share the same ledger info");
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::verify_dispute;
    use consensus_types::{
        block::Block, block_data::BlockData, quorum_cert::QuorumCert,
        vote::Vote, vote_data::VoteData,
    };
    use diem_crypto::{hash::CryptoHash, HashValue};
    use diem_types::{
        account_address::from_consensus_public_key,
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        term_state::pos_state_config::{PosStateConfig, POS_STATE_CONFIG},
        transaction::{ConflictSignature, DisputePayload},
        validator_signer::ValidatorSigner,
    };
    use std::collections::BTreeMap;

    const TRANSITION: u64 = 100;
    const BEFORE: u64 = 0;

    fn install_config() {
        // `POS_STATE_CONFIG` is a set-once process global; the executor crate
        // has no other test seeding it, so a single set is safe.
        POS_STATE_CONFIG
            .set(PosStateConfig::new(
                60,
                1,
                1,
                0,
                0,
                u64::MAX,
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                0,
                0,
                60,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                TRANSITION,
            ))
            .expect("POS_STATE_CONFIG already set");
    }

    /// A QC whose certified block is at round 0, so `QuorumCert::verify`
    /// short-circuits as a genesis QC (no signatures needed). Good enough to
    /// build well-formed evidence blocks; the strict path never verifies it.
    fn genesis_qc() -> QuorumCert {
        let bi = BlockInfo::new(
            1,
            0,
            HashValue::zero(),
            HashValue::zero(),
            0,
            0,
            None,
            None,
        );
        let vote_data = VoteData::new(bi.clone(), bi.clone());
        let li = LedgerInfo::new(bi, vote_data.hash());
        QuorumCert::new(
            vote_data,
            LedgerInfoWithSignatures::new(li, BTreeMap::new()),
        )
    }

    #[test]
    fn verify_dispute_conflict_gating() {
        install_config();

        let signer = ValidatorSigner::random([7u8; 32]);
        let bls = signer.public_key();
        let vrf = signer.vrf_public_key().unwrap();
        let address = from_consensus_public_key(&bls, &vrf);

        // Distinct `proposed_id`s give the votes distinct `LedgerInfo`s.
        let make_vote = |proposed_id: HashValue| -> Vote {
            let parent = BlockInfo::new(
                1,
                1,
                HashValue::zero(),
                HashValue::zero(),
                0,
                0,
                None,
                None,
            );
            let proposed = BlockInfo::new(
                1,
                2,
                proposed_id,
                HashValue::zero(),
                0,
                0,
                None,
                None,
            );
            let vote_data = VoteData::new(proposed, parent);
            let li = LedgerInfo::new(BlockInfo::empty(), HashValue::zero());
            Vote::new(vote_data, address, li, &signer)
        };
        let make_proposal = |timestamp: u64| -> Block {
            let block_data = BlockData::new_proposal(
                vec![],
                address,
                2,
                timestamp,
                genesis_qc(),
            );
            Block::new_proposal_from_block_data(block_data, &signer)
        };

        let vote_dispute = |v1: &Vote, v2: &Vote| DisputePayload {
            address,
            bls_pub_key: bls.clone(),
            vrf_pub_key: vrf.clone(),
            conflicting_votes: ConflictSignature::Vote((
                bcs::to_bytes(v1).unwrap(),
                bcs::to_bytes(v2).unwrap(),
            )),
        };
        let proposal_dispute = |b1: &Block, b2: &Block| DisputePayload {
            address,
            bls_pub_key: bls.clone(),
            vrf_pub_key: vrf.clone(),
            conflicting_votes: ConflictSignature::Proposal((
                bcs::to_bytes(b1).unwrap(),
                bcs::to_bytes(b2).unwrap(),
            )),
        };

        let va = make_vote(HashValue::new([1u8; 32]));
        let vb = make_vote(HashValue::new([2u8; 32]));
        assert_ne!(va.ledger_info().hash(), vb.ledger_info().hash());

        // Genuine equivocation: accepted before and after the transition.
        assert!(verify_dispute(&vote_dispute(&va, &vb), BEFORE));
        assert!(verify_dispute(&vote_dispute(&va, &vb), TRANSITION));

        // Duplicated vote: accepted before the transition, rejected after.
        assert!(verify_dispute(&vote_dispute(&va, &va), BEFORE));
        assert!(!verify_dispute(&vote_dispute(&va, &va), TRANSITION));

        // Same `LedgerInfo`, different serialized bytes (timeout signature
        // added): accepted before the transition, rejected after.
        let regular = make_vote(HashValue::new([1u8; 32]));
        let mut timeout = regular.clone();
        timeout.add_timeout_signature(signer.sign(&timeout.timeout()));
        assert_ne!(
            bcs::to_bytes(&regular).unwrap(),
            bcs::to_bytes(&timeout).unwrap()
        );
        assert_eq!(regular.ledger_info().hash(), timeout.ledger_info().hash());
        assert!(verify_dispute(&vote_dispute(&regular, &timeout), BEFORE));
        assert!(!verify_dispute(
            &vote_dispute(&regular, &timeout),
            TRANSITION
        ));

        // Proposal branch: two distinct proposals (different timestamp ->
        // different id) by the target are a genuine equivocation.
        let pa = make_proposal(1000);
        let pb = make_proposal(2000);
        assert_ne!(pa.id(), pb.id());
        assert!(verify_dispute(&proposal_dispute(&pa, &pb), TRANSITION));

        // Identical proposal: same id -> rejected after the transition.
        assert!(!verify_dispute(&proposal_dispute(&pa, &pa), TRANSITION));

        // NIL blocks have no proposer signature: accepted before the
        // transition, rejected after.
        let na = Block::new_nil(2, genesis_qc());
        let nb = Block::new_nil(2, genesis_qc());
        assert!(verify_dispute(&proposal_dispute(&na, &nb), BEFORE));
        assert!(!verify_dispute(&proposal_dispute(&na, &nb), TRANSITION));
    }
}
