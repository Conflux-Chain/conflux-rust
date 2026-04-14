use std::collections::BTreeMap;

use consensus_types::{block::Block, vote::Vote};
use diem_logger::{error as diem_error, prelude::*};
use diem_state_view::StateView;
use diem_types::{
    account_address::from_consensus_public_key,
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
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
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
        if !verify_dispute(self) {
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

/// Return true if the dispute is valid.
/// Return false if the encoding is invalid or the provided signatures are
/// not from the same round.
pub fn verify_dispute(dispute: &DisputePayload) -> bool {
    let computed_address =
        from_consensus_public_key(&dispute.bls_pub_key, &dispute.vrf_pub_key);
    if dispute.address != computed_address {
        diem_trace!("Incorrect address and public keys");
        return false;
    }
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
            let mut temp_map = BTreeMap::new();
            temp_map.insert(
                dispute.address,
                ValidatorConsensusInfo::new(
                    dispute.bls_pub_key.clone(),
                    Some(dispute.vrf_pub_key.clone()),
                    1,
                ),
            );
            let temp_verifier = ValidatorVerifier::new(temp_map);
            if proposal1.validate_signature(&temp_verifier).is_err()
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
            let mut temp_map = BTreeMap::new();
            temp_map.insert(
                dispute.address,
                ValidatorConsensusInfo::new(
                    dispute.bls_pub_key.clone(),
                    Some(dispute.vrf_pub_key.clone()),
                    1,
                ),
            );
            let temp_verifier = ValidatorVerifier::new(temp_map);
            if vote1.verify(&temp_verifier).is_err()
                || vote2.verify(&temp_verifier).is_err()
            {
                diem_trace!("dispute vote verification error: vote1_r={:?} vote2_r={:?}", vote1.verify(&temp_verifier), vote2.verify(&temp_verifier));
                return false;
            }
        }
    }
    true
}
