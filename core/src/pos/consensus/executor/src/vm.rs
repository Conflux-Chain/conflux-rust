use diem_state_view::StateView;
use diem_types::{
    contract_event::ContractEvent,
    transaction::{
        Transaction, TransactionOutput, TransactionPayload, TransactionStatus,
        WriteSetPayload,
    },
    vm_status::{KeptVMStatus, StatusCode, VMStatus},
    write_set::WriteSet,
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
    ) -> Result<Vec<TransactionOutput>, VMStatus>;
}

/// A fake VM implementing VMExecutor
pub struct FakeVM;

impl VMExecutor for FakeVM {
    fn execute_block(
        transactions: Vec<Transaction>, _state_view: &dyn StateView,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        let mut vm_outputs = Vec::new();
        for transaction in transactions {
            // Execute the transaction
            match transaction {
                Transaction::BlockMetadata(_data) => {}
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
        let status = TransactionStatus::Keep(KeptVMStatus::Executed);

        TransactionOutput::new(WriteSet::default(), events, 0, status)
    }
}
