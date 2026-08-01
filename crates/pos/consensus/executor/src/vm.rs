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
    //! One `#[test]` runs every case, since `POS_STATE_CONFIG` is set-once and
    //! a second `install_config()` would panic; its body lists them in order.
    //! Cases state their expectation as `accepted`, `rejected`, or `gated`,
    //! the last meaning accepted before `cip173_transition_view` and refused
    //! after — what the fix exists for. All three assert on both sides of the
    //! transition. A genuine equivocation per branch controls that the
    //! fixtures are valid; identity cases put the bad item in either operand
    //! slot, since a bad first item short-circuits the second; dedup cases
    //! pair items whose bytes differ while the statement the target signed
    //! stays the same, or is merely re-encoded.

    use super::verify_dispute;
    use consensus_types::{
        block::Block, block_data::BlockData, quorum_cert::QuorumCert,
        vote::Vote, vote_data::VoteData,
    };
    use diem_crypto::{hash::CryptoHash, HashValue, ValidCryptoMaterial};
    use diem_types::{
        account_address::{from_consensus_public_key, AccountAddress},
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        term_state::pos_state_config::{PosStateConfig, POS_STATE_CONFIG},
        transaction::{ConflictSignature, DisputePayload},
        validator_config::{
            ConsensusPublicKey, ConsensusSignature, ConsensusVRFProof,
            ConsensusVRFPublicKey,
        },
        validator_signer::ValidatorSigner,
    };
    use std::{collections::BTreeMap, convert::TryFrom};

    const TRANSITION: u64 = 100;
    const BEFORE: u64 = 0;

    /// Every piece of evidence below shares this epoch/round, so the epoch and
    /// round comparisons never short-circuit ahead of the check under test.
    const EPOCH: u64 = 1;
    const ROUND: u64 = 2;
    const TIMESTAMP: u64 = 1000;

    #[track_caller]
    fn accepted(evidence: &DisputePayload) {
        assert!(verify_dispute(evidence, BEFORE));
        assert!(verify_dispute(evidence, TRANSITION));
    }

    #[track_caller]
    fn gated(evidence: &DisputePayload) {
        assert!(verify_dispute(evidence, BEFORE));
        assert!(!verify_dispute(evidence, TRANSITION));
    }

    #[track_caller]
    fn rejected(evidence: &DisputePayload) {
        assert!(!verify_dispute(evidence, BEFORE));
        assert!(!verify_dispute(evidence, TRANSITION));
    }

    /// The last argument is `cip173_transition_view`; `M` leaves every other
    /// transition inert.
    fn install_config() {
        const M: u64 = u64::MAX;
        POS_STATE_CONFIG
            .set(PosStateConfig::new(
                60, 1, 1, 0, 0, M, 0, 0, M, M, M, 0, 0, 60, M, M, TRANSITION,
            ))
            .expect("POS_STATE_CONFIG already set");
    }

    /// The validator a dispute accuses. `address` stays derived from the two
    /// public keys because `verify_dispute` recomputes and compares it.
    struct Target {
        address: AccountAddress,
        bls: ConsensusPublicKey,
        vrf: ConsensusVRFPublicKey,
    }

    impl Target {
        fn of(signer: &ValidatorSigner) -> Self {
            let bls = signer.public_key();
            let vrf = signer.vrf_public_key().unwrap();
            let address = from_consensus_public_key(&bls, &vrf);
            Self { address, bls, vrf }
        }

        fn dispute(&self, conflict: ConflictSignature) -> DisputePayload {
            DisputePayload {
                address: self.address,
                bls_pub_key: self.bls.clone(),
                vrf_pub_key: self.vrf.clone(),
                conflicting_votes: conflict,
            }
        }

        fn votes(&self, v1: &Vote, v2: &Vote) -> DisputePayload {
            self.dispute(ConflictSignature::Vote((
                bcs::to_bytes(v1).unwrap(),
                bcs::to_bytes(v2).unwrap(),
            )))
        }

        fn blocks(&self, b1: &Block, b2: &Block) -> DisputePayload {
            self.raw_blocks(
                bcs::to_bytes(b1).unwrap(),
                bcs::to_bytes(b2).unwrap(),
            )
        }

        fn raw_blocks(&self, b1: Vec<u8>, b2: Vec<u8>) -> DisputePayload {
            self.dispute(ConflictSignature::Proposal((b1, b2)))
        }
    }

    fn block_info(round: u64, id: HashValue) -> BlockInfo {
        BlockInfo::new(EPOCH, round, id, HashValue::zero(), 0, 0, None, None)
    }

    /// Round 0 makes `QuorumCert::verify` short-circuit, so the QC never needs
    /// real signatures.
    fn genesis_qc(parent: u8) -> QuorumCert {
        let bi = block_info(0, HashValue::new([parent; 32]));
        let vote_data = VoteData::new(bi.clone(), bi.clone());
        let li = LedgerInfo::new(bi, vote_data.hash());
        QuorumCert::new(
            vote_data,
            LedgerInfoWithSignatures::new(li, BTreeMap::new()),
        )
    }

    /// Evidence varies only in the parent it builds on — never in the proposed
    /// block or the timestamp — so a dedup keyed on either of those instead of
    /// on the whole signed statement cannot survive the positive controls.
    fn make_vote(
        signer: &ValidatorSigner, author: AccountAddress, parent: u8,
    ) -> Vote {
        let vote_data = VoteData::new(
            block_info(ROUND, HashValue::new([0xAA; 32])),
            block_info(ROUND - 1, HashValue::new([parent; 32])),
        );
        let li = LedgerInfo::new(BlockInfo::empty(), HashValue::zero());
        Vote::new(vote_data, author, li, signer)
    }

    fn proposal_data(author: AccountAddress, parent: u8) -> BlockData {
        BlockData::new_proposal(
            vec![],
            author,
            ROUND,
            TIMESTAMP,
            genesis_qc(parent),
        )
    }

    fn make_proposal(
        signer: &ValidatorSigner, author: AccountAddress, parent: u8,
    ) -> Block {
        Block::new_proposal_from_block_data(
            proposal_data(author, parent),
            signer,
        )
    }

    /// No constructor yields a `Proposal` block with a missing or
    /// non-canonically encoded signature, so those are built as wire bytes;
    /// the call site asserts this matches a real `Block` encoding.
    fn proposal_wire_bytes(
        data: &BlockData, signature: Option<&[u8]>,
    ) -> Vec<u8> {
        bcs::to_bytes(&(
            data,
            signature.map(<[u8]>::to_vec),
            None::<(u64, ConsensusVRFProof)>,
        ))
        .unwrap()
    }

    /// Compressed G2 is the 96-byte x coordinate flagged with `0x80`, plus
    /// `0x20` when y is the larger root; try both rather than recompute it.
    fn compressed_signature_bytes(signature: &ConsensusSignature) -> Vec<u8> {
        let uncompressed = ValidCryptoMaterial::to_bytes(signature);
        for sort_flag in &[0x00u8, 0x20u8] {
            let mut candidate = uncompressed[..96].to_vec();
            candidate[0] |= 0x80 | sort_flag;
            if let Ok(decoded) =
                ConsensusSignature::try_from(candidate.as_slice())
            {
                if decoded == *signature {
                    return candidate;
                }
            }
        }
        panic!("no compressed encoding decodes back to the same signature");
    }

    /// `verify_dispute` never checks the VRF proof, so any bytes work.
    fn dummy_vrf_proof() -> ConsensusVRFProof {
        ConsensusVRFProof::try_from(&[][..]).unwrap()
    }

    #[test]
    fn verify_dispute_conflict_gating() {
        install_config();

        let signer = ValidatorSigner::random([7u8; 32]);
        let other = ValidatorSigner::random([9u8; 32]);
        let target = Target::of(&signer);

        vote_conflict_gating(&signer, &target);
        proposal_conflict_gating(&signer, &target);
        vote_identity_is_bound_to_the_accused(&signer, &other, &target);
        proposal_identity_is_bound_to_the_accused(&signer, &other, &target);
        unsigned_proposal_is_not_evidence(&signer, &target);
        fields_outside_block_data_cannot_forge_a_conflict(&signer, &target);
    }

    fn vote_conflict_gating(signer: &ValidatorSigner, target: &Target) {
        let va = make_vote(signer, target.address, 1);
        let vb = make_vote(signer, target.address, 2);
        // Equivocation over one proposed block: the key is the signed
        // `LedgerInfo`, not the proposed id.
        assert_eq!(
            va.vote_data().proposed().id(),
            vb.vote_data().proposed().id()
        );
        assert_ne!(va.ledger_info().hash(), vb.ledger_info().hash());
        accepted(&target.votes(&va, &vb));
        gated(&target.votes(&va, &va));

        // Adding the timeout signature changes the bytes but not the
        // `LedgerInfo` it signs, so byte inequality is not conflict.
        let mut timeout = va.clone();
        timeout.add_timeout_signature(signer.sign(&timeout.timeout()));
        assert_ne!(
            bcs::to_bytes(&va).unwrap(),
            bcs::to_bytes(&timeout).unwrap()
        );
        assert_eq!(va.ledger_info().hash(), timeout.ledger_info().hash());
        gated(&target.votes(&va, &timeout));
    }

    fn proposal_conflict_gating(signer: &ValidatorSigner, target: &Target) {
        let pa = make_proposal(signer, target.address, 1);
        let pb = make_proposal(signer, target.address, 2);
        // Equivocation at one timestamp: the key is the whole `block_data`.
        assert_eq!(pa.timestamp_usecs(), pb.timestamp_usecs());
        assert_ne!(pa.id(), pb.id());
        accepted(&target.blocks(&pa, &pb));
        gated(&target.blocks(&pa, &pa));

        // NIL blocks carry no proposer signature at all.
        let na = Block::new_nil(ROUND, genesis_qc(1));
        let nb = Block::new_nil(ROUND, genesis_qc(2));
        gated(&target.blocks(&na, &nb));
    }

    fn vote_identity_is_bound_to_the_accused(
        signer: &ValidatorSigner, other: &ValidatorSigner, target: &Target,
    ) {
        let impostor = Target::of(other).address;
        let genuine = make_vote(signer, target.address, 1);
        // Another validator's own equivocation, replayed against the target.
        let foreign_a = make_vote(other, impostor, 1);
        let foreign_b = make_vote(other, impostor, 2);
        // `author` is the target but the signature is the impostor's.
        let forged = make_vote(other, target.address, 2);
        // Signed by the target but naming someone else: only the author
        // comparison rejects this one.
        let misnamed = make_vote(signer, impostor, 2);

        rejected(&target.votes(&foreign_a, &foreign_b));
        rejected(&target.votes(&genuine, &foreign_b));
        rejected(&target.votes(&forged, &genuine));
        rejected(&target.votes(&genuine, &forged));
        rejected(&target.votes(&misnamed, &genuine));
        rejected(&target.votes(&genuine, &misnamed));
    }

    fn proposal_identity_is_bound_to_the_accused(
        signer: &ValidatorSigner, other: &ValidatorSigner, target: &Target,
    ) {
        let impostor = Target::of(other).address;
        let genuine = make_proposal(signer, target.address, 1);
        // Another validator's own equivocation, replayed against the target.
        let foreign_a = make_proposal(other, impostor, 1);
        let foreign_b = make_proposal(other, impostor, 2);
        // `author` is the target but the signature is the impostor's.
        let forged = make_proposal(other, target.address, 2);
        // Signed by the target but naming someone else: only the author
        // comparison rejects this one.
        let misnamed = make_proposal(signer, impostor, 2);

        rejected(&target.blocks(&foreign_a, &foreign_b));
        rejected(&target.blocks(&genuine, &foreign_b));
        rejected(&target.blocks(&forged, &genuine));
        rejected(&target.blocks(&genuine, &forged));
        rejected(&target.blocks(&misnamed, &genuine));
        rejected(&target.blocks(&genuine, &misnamed));
    }

    fn unsigned_proposal_is_not_evidence(
        signer: &ValidatorSigner, target: &Target,
    ) {
        let unsigned =
            proposal_wire_bytes(&proposal_data(target.address, 2), None);
        let decoded: Block = bcs::from_bytes(&unsigned).unwrap();
        assert!(decoded.signature().is_none());
        assert_eq!(decoded.author(), Some(target.address));

        // A different parent gives the genuine companion a different id, so the
        // missing signature is the only thing left to reject the pair.
        let genuine =
            bcs::to_bytes(&make_proposal(signer, target.address, 1)).unwrap();
        rejected(&target.raw_blocks(unsigned.clone(), genuine.clone()));
        rejected(&target.raw_blocks(genuine, unsigned));
    }

    /// `signature` and `vrf_nonce_and_proof` sit on `Block`, outside the
    /// signed `block_data`, so re-encoding either forges a second block
    /// without the target's key: a G2 point has both a 96-byte compressed and
    /// a 192-byte uncompressed form and `g2_from_slice` accepts either, while
    /// serialization always emits the uncompressed one.
    fn fields_outside_block_data_cannot_forge_a_conflict(
        signer: &ValidatorSigner, target: &Target,
    ) {
        let data = proposal_data(target.address, 1);
        let signature = signer.sign(&data);
        let copy = |vrf: Option<(u64, ConsensusVRFProof)>| {
            Block::new_proposal_from_block_data_and_signature(
                data.clone(),
                signature.clone(),
                vrf,
            )
        };
        let plain = copy(None);
        let with_proof = copy(Some((1, dummy_vrf_proof())));
        let other_nonce = copy(Some((2, dummy_vrf_proof())));

        // Every copy carries the target's own valid signature, so all the
        // identity checks pass and only the equal ids reject them.
        assert_ne!(
            bcs::to_bytes(&plain).unwrap(),
            bcs::to_bytes(&with_proof).unwrap()
        );
        assert_eq!(plain.id(), with_proof.id());
        assert_eq!(with_proof.id(), other_nonce.id());
        gated(&target.blocks(&plain, &with_proof));
        gated(&target.blocks(&with_proof, &other_nonce));

        // The signature variant needs raw wire bytes; no constructor emits a
        // non-canonical encoding. The uncompressed hand-built form must equal
        // the real one, or the compressed one would test a different encoding.
        let canonical = ValidCryptoMaterial::to_bytes(&signature);
        let compressed = compressed_signature_bytes(&signature);
        assert_ne!(canonical, compressed);
        let uncompressed = proposal_wire_bytes(&data, Some(&canonical));
        assert_eq!(uncompressed, bcs::to_bytes(&plain).unwrap());
        let alternative = proposal_wire_bytes(&data, Some(&compressed));
        let decoded: Block = bcs::from_bytes(&alternative).unwrap();
        assert_eq!(decoded.id(), plain.id());
        gated(&target.raw_blocks(uncompressed, alternative));
    }
}
