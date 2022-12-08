use std::collections::BTreeMap;

use consensus_types::{block::Block, vote::Vote};
use diem_logger::{error as diem_error, prelude::*};
use diem_state_view::StateView;
use diem_types::{
    account_address::from_consensus_public_key,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    on_chain_config::{self, new_epoch_event_key, OnChainConfig, ValidatorSet},
    term_state::pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG},
    transaction::{
        authenticator::TransactionAuthenticator, ConflictSignature,
        DisputePayload, Transaction, TransactionOutput, TransactionPayload,
        TransactionStatus, WriteSetPayload,
    },
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
    vm_status::{KeptVMStatus, StatusCode, VMStatus},
    write_set::{WriteOp, WriteSetMut},
};

/// This trait describes the VM's execution interface.
pub trait VMExecutor: Send {
    // NOTE: At the moment there are no persistent caches that live past the end
    // of a block (that's why execute_block doesn't take &self.)
    // There are some cache invalidation issues around transactions publishing
    // code that need to be sorted out before that's possible.

    /// Executes a block of transactions and returns output for each one of
    /// them.
    fn execute_block(
        transactions: Vec<Transaction>, state_view: &dyn StateView,
        catch_up_mode: bool,
    ) -> Result<Vec<TransactionOutput>, VMStatus>;
}

/// A fake VM implementing VMExecutor
pub struct FakeVM;

impl VMExecutor for FakeVM {
    fn execute_block(
        transactions: Vec<Transaction>, state_view: &dyn StateView,
        catch_up_mode: bool,
    ) -> Result<Vec<TransactionOutput>, VMStatus>
    {
        let mut vm_outputs = Vec::new();
        for transaction in transactions {
            // Execute the transaction
            match transaction {
                Transaction::BlockMetadata(_) => {
                    let mut events = state_view.pos_state().get_unlock_events();
                    diem_debug!("get_unlock_events: {}", events.len());
                    // TODO(lpl): Simplify.
                    if (state_view.pos_state().current_view() + 1)
                        % POS_STATE_CONFIG.round_per_term()
                        == 0
                    {
                        let term = (state_view.pos_state().current_view() + 1)
                            / POS_STATE_CONFIG.round_per_term();
                        let (validator_verifier, vrf_seed) = state_view
                            .pos_state()
                            .get_committee_at(term)
                            .map_err(|e| {
                                diem_warn!("get_new_committee error: {:?}", e);
                                VMStatus::Error(StatusCode::CFX_INVALID_TX)
                            })?;
                        let epoch = (state_view.pos_state().current_view() + 1)
                            / POS_STATE_CONFIG.round_per_term()
                            + 1;
                        let validator_bytes = bcs::to_bytes(&EpochState::new(
                            epoch,
                            validator_verifier,
                            vrf_seed,
                        ))
                        .unwrap();
                        let contract_event = ContractEvent::new(
                            new_epoch_event_key(),
                            validator_bytes,
                        );
                        events.push(contract_event);
                    }
                    let output = Self::gen_output(events, false);
                    vm_outputs.push(output);
                }
                Transaction::UserTransaction(trans) => {
                    // TODO(lpl): Parallel verification.
                    let trans = trans.check_signature().map_err(|e| {
                        diem_trace!(
                            "invalid transactions signature: e={:?}",
                            e
                        );
                        VMStatus::Error(StatusCode::INVALID_SIGNATURE)
                    })?;
                    /* TODO(lpl): Handle pos epoch change.
                    if verify_admin_transaction && trans.is_admin_type() {
                        info!("executing admin trans");
                        // Check the voting power of signers in administrators.
                        let admins = self.validators.read();
                        if admins.is_none() {
                            bail!("Administrators are not set.");
                        }
                        let admins = admins.as_ref().unwrap();
                        let signers = trans.pubkey_account_addresses();
                        match admins.check_voting_power(signers.iter()) {
                            Ok(_) => {}
                            Err(VerifyError::TooLittleVotingPower {
                                    ..
                                }) => {
                                bail!("Not enough voting power in administrators.");
                            }
                            Err(_) => {
                                bail!(
                                    "There are signers not in administrators."
                                );
                            }
                        }
                    }
                    */
                    let payload = trans.payload();
                    let events = match payload {
                        TransactionPayload::WriteSet(
                            WriteSetPayload::Direct(change_set),
                        ) => change_set.events().to_vec(),
                        TransactionPayload::Election(election_payload) => {
                            if !catch_up_mode {
                                state_view
                                    .pos_state()
                                    .validate_election(election_payload)
                                    .map_err(|e| {
                                        diem_error!(
                                            "election tx error: {:?}",
                                            e
                                        );
                                        VMStatus::Error(
                                            StatusCode::CFX_INVALID_TX,
                                        )
                                    })?;
                            }
                            vec![election_payload.to_event()]
                        }
                        TransactionPayload::Retire(retire_payload) => {
                            vec![retire_payload.to_event()]
                        }
                        TransactionPayload::PivotDecision(pivot_decision) => {
                            if !catch_up_mode {
                                let authenticator = trans.authenticator();
                                let signature = match authenticator {
                                    TransactionAuthenticator::MultiBLS {
                                        signature,
                                    } => Ok(signature),
                                    _ => Err(VMStatus::Error(
                                        StatusCode::CFX_INVALID_TX,
                                    )),
                                }?;
                                state_view
                                    .pos_state()
                                    .validate_pivot_decision(
                                        pivot_decision,
                                        signature,
                                    )
                                    .map_err(|e| {
                                        diem_error!(
                                            "pivot decision tx error: {:?}",
                                            e
                                        );
                                        VMStatus::Error(
                                            StatusCode::CFX_INVALID_TX,
                                        )
                                    })?;
                            }
                            vec![pivot_decision.to_event()]
                        }
                        TransactionPayload::Register(register) => {
                            vec![register.to_event()]
                        }
                        TransactionPayload::UpdateVotingPower(update) => {
                            vec![update.to_event()]
                        }
                        TransactionPayload::Dispute(dispute) => {
                            state_view
                                .pos_state()
                                .validate_dispute(dispute)
                                .map_err(|e| {
                                    diem_error!("dispute tx error: {:?}", e);
                                    VMStatus::Error(StatusCode::CFX_INVALID_TX)
                                })?;
                            if !Self::verify_dispute(dispute) {
                                return Err(VMStatus::Error(
                                    StatusCode::CFX_INVALID_TX,
                                ));
                            }
                            vec![dispute.to_event()]
                        }
                        _ => {
                            return Err(VMStatus::Error(
                                StatusCode::CFX_UNEXPECTED_TX,
                            ))
                        }
                    };

                    // ensure!(
                    //     events.len() == 1,
                    //     "One transaction can contain exactly 1 event."
                    // );

                    let output = Self::gen_output(events, false);
                    vm_outputs.push(output);
                }
                Transaction::GenesisTransaction(change_set) => {
                    let events = match change_set {
                        WriteSetPayload::Direct(change_set) => {
                            change_set.events().to_vec()
                        }
                        _ => {
                            return Err(VMStatus::Error(
                                StatusCode::CFX_UNEXPECTED_TX,
                            ))
                        }
                    };
                    // ensure!(
                    //     events.len() == 1,
                    //     "One transaction can contain exactly 1 event."
                    // );

                    let output = Self::gen_output(events, true);
                    vm_outputs.push(output);
                }
            }
        }

        Ok(vm_outputs)
    }
}

impl FakeVM {
    fn gen_output(
        events: Vec<ContractEvent>, write: bool,
    ) -> TransactionOutput {
        let new_epoch_event_key = on_chain_config::new_epoch_event_key();
        let status = TransactionStatus::Keep(KeptVMStatus::Executed);
        let mut write_set = WriteSetMut::default();

        // TODO(linxi): support other event key
        if write {
            for event in &events {
                if *event.key() == new_epoch_event_key {
                    write_set.push((
                        ValidatorSet::CONFIG_ID.access_path(),
                        WriteOp::Value(event.event_data().to_vec()),
                    ));
                }
            }
        }

        TransactionOutput::new(write_set.freeze().unwrap(), events, 0, status)
    }

    /// Return true if the dispute is valid.
    /// Return false if the encoding is invalid or the provided signatures are
    /// not from the same round.
    pub fn verify_dispute(dispute: &DisputePayload) -> bool {
        let computed_address = from_consensus_public_key(
            &dispute.bls_pub_key,
            &dispute.vrf_pub_key,
        );
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
                if proposal1 == proposal2 {
                    diem_trace!(
                        "Two same proposals are claimed to be conflict"
                    );
                    return false;
                }
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
                if vote1 == vote2 {
                    diem_trace!("Two same votes are claimed to be conflict");
                    return false;
                }
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
}
