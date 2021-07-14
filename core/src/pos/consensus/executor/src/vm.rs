use diem_logger::error as diem_error;
use diem_state_view::StateView;
use diem_types::{
    access_path::AccessPath,
    account_config::pivot_chain_select_address,
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    on_chain_config::{self, config_address, OnChainConfig, ValidatorSet},
    transaction::{
        Transaction, TransactionOutput, TransactionPayload, TransactionStatus,
        WriteSetPayload,
    },
    vm_status::{KeptVMStatus, StatusCode, VMStatus},
    write_set::{WriteOp, WriteSet, WriteSetMut},
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
                Transaction::BlockMetadata(_data) => {
                    let unlock_events =
                        state_view.pos_state().get_unlock_events();
                    let output = Self::gen_output(unlock_events);
                    vm_outputs.push(output);
                }
                Transaction::UserTransaction(trans) => {
                    // TODO(lpl): Parallel verification.
                    let trans = trans.check_signature().map_err(|_| {
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
                            if !catch_up_mode {
                                state_view
                                    .pos_state()
                                    .validate_retire(retire_payload)
                                    .map_err(|e| {
                                        diem_error!(
                                            "retirement tx error: {:?}",
                                            e
                                        );
                                        VMStatus::Error(
                                            StatusCode::CFX_INVALID_TX,
                                        )
                                    })?;
                            }
                            vec![retire_payload.to_event()]
                        }
                        TransactionPayload::PivotDecision(pivot_decision) => {
                            // The validation is handled in
                            // `post_process_state_compute_result`.
                            vec![pivot_decision.to_event()]
                        }
                        TransactionPayload::Register(register) => {
                            vec![register.to_event()]
                        }
                        TransactionPayload::UpdateVotingPower(update) => {
                            vec![update.to_event()]
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

                    let output = Self::gen_output(events);
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

                    let output = Self::gen_output(events);
                    vm_outputs.push(output);
                }
            }
        }

        Ok(vm_outputs)
    }
}

impl FakeVM {
    fn gen_output(events: Vec<ContractEvent>) -> TransactionOutput {
        let new_epoch_event_key = on_chain_config::new_epoch_event_key();
        let pivot_select_event_key =
            PivotBlockDecision::pivot_select_event_key();
        let status = TransactionStatus::Keep(KeptVMStatus::Executed);
        let mut write_set = WriteSetMut::default();

        // TODO(linxi): support other event key
        for event in &events {
            if *event.key() == new_epoch_event_key {
                write_set.push((
                    ValidatorSet::CONFIG_ID.access_path(),
                    WriteOp::Value(event.event_data().to_vec()),
                ));
                /*
                } else if *event.key() == pivot_select_event_key {
                    write_set.push((
                        AccessPath {
                            address: pivot_chain_select_address(),
                            path: pivot_select_event_key.to_vec(),
                        },
                        WriteOp::Value(event.event_data().to_vec()),
                    ));

                } else {
                    todo!()
                     */
            }
        }

        TransactionOutput::new(write_set.freeze().unwrap(), events, 0, status)
    }
}
