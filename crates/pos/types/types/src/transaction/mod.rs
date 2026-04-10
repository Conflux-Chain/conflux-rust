// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    ops::Deref,
};

use anyhow::{ensure, format_err, Error, Result};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

pub use change_set::ChangeSet;
use diem_crypto::{
    hash::{CryptoHash, EventAccumulatorHasher},
    traits::SigningKey,
    HashValue, PrivateKey, VRFProof,
};
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
use pow_types::StakingEvent;

use crate::{
    account_address::AccountAddress,
    block_info::PivotBlockDecision,
    block_metadata::BlockMetadata,
    chain_id::ChainId,
    contract_event::ContractEvent,
    ledger_info::LedgerInfo,
    proof::{accumulator::InMemoryAccumulator, TransactionInfoWithProof},
    term_state::{
        DisputeEvent, ElectionEvent, NodeID, RegisterEvent, RetireEvent,
        UpdateVotingPowerEvent,
    },
    transaction::authenticator::{
        TransactionAuthenticator, TransactionAuthenticatorUnchecked,
    },
    validator_config::{
        ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
        ConsensusVRFProof, ConsensusVRFPublicKey, MultiConsensusSignature,
    },
    vm_status::{
        DiscardedVMStatus, KeptVMStatus, StatusCode, StatusType, VMStatus,
    },
};

pub mod authenticator;
mod change_set;

pub type Version = u64; // Height - also used for MVCC in StateDB

// In StateDB, things readable by the genesis transaction are under this
// version.
pub const PRE_GENESIS_VERSION: Version = u64::max_value();

/// RawTransaction is the portion of a transaction that a client signs.
#[derive(
    Clone,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    CryptoHasher,
    BCSCryptoHash,
)]
pub struct RawTransaction {
    /// Sender's address.
    sender: AccountAddress,

    /// The transaction payload, e.g., a script to execute.
    payload: TransactionPayload,

    /// Expiration timestamp for this transaction, represented
    /// as seconds from the Unix Epoch. If the current blockchain timestamp
    /// is greater than or equal to this time, then the transaction has
    /// expired and will be discarded. This can be set to a large value far
    /// in the future to indicate that a transaction does not expire.
    expiration_timestamp_secs: u64,

    /// Chain ID of the Diem network this transaction is intended for.
    chain_id: ChainId,
}

impl RawTransaction {
    /// Create a new `RawTransaction` with a payload.
    ///
    /// It can be either to publish a module, to execute a script, or to issue a
    /// writeset transaction.
    pub fn new(
        sender: AccountAddress, payload: TransactionPayload,
        expiration_timestamp_secs: u64, chain_id: ChainId,
    ) -> Self {
        RawTransaction {
            sender,
            payload,
            expiration_timestamp_secs,
            chain_id,
        }
    }

    pub fn new_pivot_decision(
        sender: AccountAddress, pivot_decision: PivotBlockDecision,
        chain_id: ChainId,
    ) -> Self {
        RawTransaction {
            sender,
            payload: TransactionPayload::PivotDecision(pivot_decision),
            // Write-set transactions are special and important and shouldn't
            // expire.
            expiration_timestamp_secs: u64::max_value(),
            chain_id,
        }
    }

    pub fn new_election(
        sender: AccountAddress, election_payload: ElectionPayload,
        chain_id: ChainId,
    ) -> Self {
        RawTransaction {
            sender,
            payload: TransactionPayload::Election(election_payload),
            // Write-set transactions are special and important and shouldn't
            // expire.
            expiration_timestamp_secs: u64::max_value(),
            chain_id,
        }
    }

    pub fn new_dispute(
        sender: AccountAddress, dispute_payload: DisputePayload,
    ) -> Self {
        RawTransaction {
            sender,
            payload: TransactionPayload::Dispute(dispute_payload),
            // Write-set transactions are special and important and shouldn't
            // expire.
            expiration_timestamp_secs: u64::max_value(),
            chain_id: Default::default(),
        }
    }

    pub fn new_retire(
        sender: AccountAddress, retire_payload: RetirePayload,
    ) -> Self {
        RawTransaction {
            sender,
            payload: TransactionPayload::Retire(retire_payload),
            // Write-set transactions are special and important and shouldn't
            // expire.
            expiration_timestamp_secs: u64::max_value(),
            chain_id: Default::default(),
        }
    }

    pub fn from_staking_event(
        staking_event: &StakingEvent, sender: AccountAddress,
    ) -> Result<Self> {
        let payload = match staking_event {
            StakingEvent::Register(
                addr_h256,
                bls_pub_key_bytes,
                vrf_pub_key_bytes,
            ) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                let public_key =
                    ConsensusPublicKey::try_from(bls_pub_key_bytes.as_slice())?;
                let vrf_public_key = ConsensusVRFPublicKey::try_from(
                    vrf_pub_key_bytes.as_slice(),
                )?;
                let node_id =
                    NodeID::new(public_key.clone(), vrf_public_key.clone());
                ensure!(
                    node_id.addr == addr,
                    "register event has unmatching address and keys"
                );
                TransactionPayload::Register(RegisterPayload {
                    public_key,
                    vrf_public_key,
                })
            }
            StakingEvent::IncreaseStake(addr_h256, updated_voting_power) => {
                let addr = AccountAddress::from_bytes(addr_h256)?;
                TransactionPayload::UpdateVotingPower(
                    UpdateVotingPowerPayload {
                        node_address: addr,
                        voting_power: *updated_voting_power,
                    },
                )
            }
            StakingEvent::Retire(identifier, votes) => {
                TransactionPayload::Retire(RetirePayload {
                    node_id: AccountAddress::new(identifier.0),
                    votes: *votes,
                })
            }
        };
        Ok(RawTransaction {
            sender,
            payload,
            // Write-set transactions are special and important and shouldn't
            // expire.
            expiration_timestamp_secs: u64::max_value(),
            chain_id: Default::default(),
        })
    }

    /// Signs the given `RawTransaction`. Note that this consumes the
    /// `RawTransaction` and turns it into a `SignatureCheckedTransaction`.
    ///
    /// For a transaction that has just been signed, its signature is expected
    /// to be valid.
    pub fn sign(
        self, private_key: &ConsensusPrivateKey,
    ) -> Result<SignatureCheckedTransaction> {
        let signature = match self.payload {
            TransactionPayload::PivotDecision(ref pivot_decision) => {
                private_key.sign(pivot_decision)
            }
            _ => private_key.sign(&self),
        };
        let public_key = private_key.public_key();
        Ok(SignatureCheckedTransaction(SignedTransaction::new(
            self, public_key, signature,
        )))
    }

    pub fn into_payload(self) -> TransactionPayload { self.payload }

    /// Return the sender of this transaction.
    pub fn sender(&self) -> AccountAddress { self.sender }
}

/// Different kinds of transactions.
///
/// **BCS serialization note:** Variant indices must remain stable for
/// database compatibility. Indices 1-3 are legacy Diem Move variants that
/// were never used in Conflux PoS but must be preserved as placeholders.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransactionPayload {
    /// A system maintenance transaction.
    WriteSet(WriteSetPayload),
    /// Legacy Diem variant (index 1). Never used in Conflux PoS.
    #[doc(hidden)]
    _LegacyScript,
    /// Legacy Diem variant (index 2). Never used in Conflux PoS.
    #[doc(hidden)]
    _LegacyModule,
    /// Legacy Diem variant (index 3). Never used in Conflux PoS.
    #[doc(hidden)]
    _LegacyScriptFunction,

    /// A transaction that add a node to committee candidates.
    Election(ElectionPayload),

    /// A transaction that sets a node to `Retire` status so the node will not
    /// be elected.
    Retire(RetirePayload),

    Register(RegisterPayload),

    UpdateVotingPower(UpdateVotingPowerPayload),

    PivotDecision(PivotBlockDecision),

    Dispute(DisputePayload),
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElectionPayload {
    pub public_key: ConsensusPublicKey,
    pub vrf_public_key: ConsensusVRFPublicKey,
    pub target_term: u64,
    pub vrf_proof: ConsensusVRFProof,
}

impl ElectionPayload {
    pub fn to_event(&self) -> ContractEvent {
        let event = ElectionEvent::new(
            self.public_key.clone(),
            self.vrf_public_key.clone(),
            self.vrf_proof.to_hash().unwrap(),
            self.target_term,
        );
        ContractEvent::new(
            ElectionEvent::event_key(),
            bcs::to_bytes(&event).unwrap(),
        )
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetirePayload {
    pub node_id: AccountAddress,
    pub votes: u64,
}

impl RetirePayload {
    pub fn to_event(&self) -> ContractEvent {
        let event = RetireEvent::new(self.node_id, self.votes);
        ContractEvent::new(
            RetireEvent::event_key(),
            bcs::to_bytes(&event).unwrap(),
        )
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    pub public_key: ConsensusPublicKey,
    pub vrf_public_key: ConsensusVRFPublicKey,
}

impl RegisterPayload {
    pub fn to_event(&self) -> ContractEvent {
        let event = RegisterEvent::new(
            self.public_key.clone(),
            self.vrf_public_key.clone(),
        );
        ContractEvent::new(
            RegisterEvent::event_key(),
            bcs::to_bytes(&event).unwrap(),
        )
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVotingPowerPayload {
    pub node_address: AccountAddress,
    pub voting_power: u64,
}

impl UpdateVotingPowerPayload {
    pub fn to_event(&self) -> ContractEvent {
        let event = UpdateVotingPowerEvent::new(
            self.node_address.clone(),
            self.voting_power,
        );
        ContractEvent::new(
            UpdateVotingPowerEvent::event_key(),
            bcs::to_bytes(&event).unwrap(),
        )
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisputePayload {
    pub address: AccountAddress,
    pub bls_pub_key: ConsensusPublicKey,
    pub vrf_pub_key: ConsensusVRFPublicKey,
    pub conflicting_votes: ConflictSignature,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConflictSignature {
    // Use raw bytes instead of `Proposal` or `Vote` to avoid dependency loop.
    Proposal((Vec<u8>, Vec<u8>)),
    Vote((Vec<u8>, Vec<u8>)),
}

impl DisputePayload {
    pub fn to_event(&self) -> ContractEvent {
        let event = DisputeEvent {
            node_id: self.address,
        };
        ContractEvent::new(
            DisputeEvent::event_key(),
            bcs::to_bytes(&event).unwrap(),
        )
    }
}

/// WriteSet transaction payload.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum WriteSetPayload {
    /// Directly passing in the WriteSet.
    Direct(ChangeSet),
}

/// A transaction that has been signed.
///
/// A `SignedTransaction` is a single transaction that can be atomically
/// executed. Clients submit these to validator nodes, and the validator and
/// executor submits these to the VM.
///
/// **IMPORTANT:** The signature of a `SignedTransaction` is not guaranteed to
/// be verified. For a transaction whose signature is statically guaranteed to
/// be verified, see [`SignatureCheckedTransaction`].
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The raw transaction
    raw_txn: RawTransaction,

    /// Public key and signature to authenticate
    authenticator: TransactionAuthenticator,
}

#[derive(Deserialize)]
pub struct SignedTransactionUnchecked {
    pub raw_txn: RawTransaction,
    pub authenticator: TransactionAuthenticatorUnchecked,
}

impl From<SignedTransactionUnchecked> for SignedTransaction {
    fn from(t: SignedTransactionUnchecked) -> Self {
        Self {
            raw_txn: t.raw_txn,
            authenticator: t.authenticator.into(),
        }
    }
}

/// A transaction for which the signature has been verified. Created by
/// [`SignedTransaction::check_signature`] and [`RawTransaction::sign`].
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignatureCheckedTransaction(SignedTransaction);

impl SignatureCheckedTransaction {
    /// Returns the `SignedTransaction` within.
    pub fn into_inner(self) -> SignedTransaction { self.0 }

    /// Returns the `RawTransaction` within.
    pub fn into_raw_transaction(self) -> RawTransaction {
        self.0.into_raw_transaction()
    }
}

impl Deref for SignatureCheckedTransaction {
    type Target = SignedTransaction;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl fmt::Debug for SignedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SignedTransaction {{ \n \
             {{ raw_txn: {:#?}, \n \
             authenticator: {:#?}, \n \
             }} \n \
             }}",
            self.raw_txn, self.authenticator
        )
    }
}

impl SignedTransaction {
    pub fn new(
        raw_txn: RawTransaction, public_key: ConsensusPublicKey,
        signature: ConsensusSignature,
    ) -> SignedTransaction {
        let authenticator =
            TransactionAuthenticator::bls(public_key, signature);
        SignedTransaction {
            raw_txn,
            authenticator,
        }
    }

    pub fn new_multisig(
        raw_txn: RawTransaction, signatures: Vec<(ConsensusSignature, usize)>,
    ) -> SignedTransaction {
        let signature = MultiConsensusSignature::new(signatures).unwrap();
        let authenticator = TransactionAuthenticator::multi_bls(signature);
        SignedTransaction {
            raw_txn,
            authenticator,
        }
    }

    pub fn authenticator(&self) -> TransactionAuthenticator {
        self.authenticator.clone()
    }

    pub fn raw_txn(&self) -> RawTransaction { self.raw_txn.clone() }

    pub fn hash(&self) -> HashValue { self.raw_txn.hash() }

    pub fn sender(&self) -> AccountAddress { self.raw_txn.sender }

    pub fn into_raw_transaction(self) -> RawTransaction { self.raw_txn }

    pub fn chain_id(&self) -> ChainId { self.raw_txn.chain_id }

    pub fn payload(&self) -> &TransactionPayload { &self.raw_txn.payload }

    pub fn expiration_timestamp_secs(&self) -> u64 {
        self.raw_txn.expiration_timestamp_secs
    }

    pub fn raw_txn_bytes_len(&self) -> usize {
        bcs::to_bytes(&self.raw_txn)
            .expect("Unable to serialize RawTransaction")
            .len()
    }

    /// Checks that the signature of given transaction. Returns
    /// `Ok(SignatureCheckedTransaction)` if the signature is valid.
    pub fn check_signature(self) -> Result<SignatureCheckedTransaction> {
        match self.payload() {
            TransactionPayload::PivotDecision(pivot_decision) => {
                self.authenticator.verify(pivot_decision)?
            }
            _ => self.authenticator.verify(&self.raw_txn)?,
        }
        Ok(SignatureCheckedTransaction(self))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionWithProof {
    pub version: Version,
    pub transaction: Transaction,
    pub events: Option<Vec<ContractEvent>>,
    pub proof: TransactionInfoWithProof,
}

impl TransactionWithProof {
    pub fn new(
        version: Version, transaction: Transaction,
        events: Option<Vec<ContractEvent>>, proof: TransactionInfoWithProof,
    ) -> Self {
        Self {
            version,
            transaction,
            events,
            proof,
        }
    }

    /// Verifies the transaction with the proof, both carried by `self`.
    ///
    /// A few things are ensured if no error is raised:
    ///   1. This transaction exists in the ledger represented by `ledger_info`.
    ///   2. This transaction is a `UserTransaction`.
    ///   3. And this user transaction has the same `version`, `sender`, and
    /// `sequence_number` as      indicated by the parameter list. If any of
    /// these parameter is unknown to the call site      that is supposed to
    /// be informed via this struct, get it from the struct itself, such
    ///      as version and sender.
    pub fn verify_user_txn(
        &self, ledger_info: &LedgerInfo, version: Version,
        sender: AccountAddress,
    ) -> Result<()> {
        let signed_transaction = self.transaction.as_signed_user_txn()?;

        ensure!(
            self.version == version,
            "Version ({}) is not expected ({}).",
            self.version,
            version,
        );
        ensure!(
            signed_transaction.sender() == sender,
            "Sender ({}) not expected ({}).",
            signed_transaction.sender(),
            sender,
        );
        let txn_hash = self.transaction.hash();
        ensure!(
            txn_hash == self.proof.transaction_info().transaction_hash,
            "Transaction hash ({}) not expected ({}).",
            txn_hash,
            self.proof.transaction_info().transaction_hash,
        );

        if let Some(events) = &self.events {
            let event_hashes: Vec<_> =
                events.iter().map(ContractEvent::hash).collect();
            let event_root_hash =
                InMemoryAccumulator::<EventAccumulatorHasher>::from_leaves(
                    &event_hashes[..],
                )
                .root_hash();
            ensure!(
                event_root_hash
                    == self.proof.transaction_info().event_root_hash,
                "Event root hash ({}) not expected ({}).",
                event_root_hash,
                self.proof.transaction_info().event_root_hash,
            );
        }

        self.proof.verify(ledger_info, version)
    }
}

/// The status of executing a transaction. The VM decides whether or not we
/// should `Keep` the transaction output or `Discard` it based upon the
/// execution of the transaction. We wrap these decisions around a `VMStatus`
/// that provides more detail on the final execution state of the VM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TransactionStatus {
    /// Discard the transaction output
    Discard(DiscardedVMStatus),

    /// Keep the transaction output
    Keep(KeptVMStatus),

    /// Retry the transaction, e.g., after a reconfiguration
    Retry,
}

impl TransactionStatus {
    pub fn status(&self) -> Result<KeptVMStatus, StatusCode> {
        match self {
            TransactionStatus::Keep(status) => Ok(status.clone()),
            TransactionStatus::Discard(code) => Err(*code),
            TransactionStatus::Retry => {
                Err(StatusCode::UNKNOWN_VALIDATION_STATUS)
            }
        }
    }

    pub fn is_discarded(&self) -> bool {
        match self {
            TransactionStatus::Discard(_) => true,
            TransactionStatus::Keep(_) => false,
            TransactionStatus::Retry => true,
        }
    }
}

impl From<VMStatus> for TransactionStatus {
    fn from(vm_status: VMStatus) -> Self {
        match vm_status.keep_or_discard() {
            Ok(recorded) => TransactionStatus::Keep(recorded),
            Err(code) => TransactionStatus::Discard(code),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum GovernanceRole {
    DiemRoot,
    TreasuryCompliance,
    Validator,
    ValidatorOperator,
    DesignatedDealer,
    NonGovernanceRole,
}

impl GovernanceRole {
    pub fn from_role_id(role_id: u64) -> Self {
        use GovernanceRole::*;
        match role_id {
            0 => DiemRoot,
            1 => TreasuryCompliance,
            2 => DesignatedDealer,
            3 => Validator,
            4 => ValidatorOperator,
            _ => NonGovernanceRole,
        }
    }

    /// The higher the number that is returned, the greater priority assigned to
    /// a transaction sent from an account with that role in mempool. All
    /// transactions sent from an account with role priority N are ranked
    /// higher than all transactions sent from accounts with role priorities <
    /// N. Transactions from accounts with equal priority are ranked base on
    /// other characteristics (e.g., gas price).
    pub fn priority(&self) -> u64 {
        use GovernanceRole::*;
        match self {
            DiemRoot => 3,
            TreasuryCompliance => 2,
            Validator | ValidatorOperator | DesignatedDealer => 1,
            NonGovernanceRole => 0,
        }
    }
}

/// The result of running the transaction through the VM validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VMValidatorResult {
    /// Result of the validation: `None` if the transaction was successfully
    /// validated or `Some(DiscardedVMStatus)` if the transaction should be
    /// discarded.
    status: Option<DiscardedVMStatus>,

    /// Score for ranking the transaction priority (e.g., based on the gas
    /// price). Only used when the status is `None`. Higher values indicate
    /// a higher priority.
    score: u64,

    /// The account role for the transaction sender, so that certain
    /// governance transactions can be prioritized above normal transactions.
    /// Only used when the status is `None`.
    governance_role: GovernanceRole,
}

impl VMValidatorResult {
    pub fn new(
        vm_status: Option<DiscardedVMStatus>, score: u64,
        governance_role: GovernanceRole,
    ) -> Self {
        debug_assert!(
            match vm_status {
                None => true,
                Some(status) => {
                    status.status_type() == StatusType::Unknown
                        || status.status_type() == StatusType::Validation
                }
            },
            "Unexpected discarded status: {:?}",
            vm_status
        );
        Self {
            status: vm_status,
            score,
            governance_role,
        }
    }

    pub fn status(&self) -> Option<DiscardedVMStatus> { self.status }

    pub fn score(&self) -> u64 { self.score }

    pub fn governance_role(&self) -> GovernanceRole { self.governance_role }
}

/// The output of executing a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionOutput {
    /// The list of events emitted during this transaction.
    events: Vec<ContractEvent>,

    /// The amount of gas used during execution.
    gas_used: u64,

    /// The execution status.
    status: TransactionStatus,
}

impl TransactionOutput {
    pub fn new(
        events: Vec<ContractEvent>, gas_used: u64, status: TransactionStatus,
    ) -> Self {
        TransactionOutput {
            events,
            gas_used,
            status,
        }
    }

    pub fn events(&self) -> &[ContractEvent] { &self.events }

    pub fn gas_used(&self) -> u64 { self.gas_used }

    pub fn status(&self) -> &TransactionStatus { &self.status }
}

/// `TransactionInfo` is the object we store in the transaction accumulator. It
/// consists of the transaction as well as the execution result of this
/// transaction.
#[derive(
    Clone,
    CryptoHasher,
    BCSCryptoHash,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionInfo {
    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Sparse Merkle Tree describing the world state at the
    /// end of this transaction.
    state_root_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during
    /// this transaction.
    event_root_hash: HashValue,

    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general
    /// error class. Execution failures and Move abort's recieve more
    /// detailed information. But other errors are generally categorized
    /// with no status code or other information
    status: KeptVMStatus,
}

impl TransactionInfo {
    /// Constructs a new `TransactionInfo` object using transaction hash, state
    /// root hash and event root hash.
    pub fn new(
        transaction_hash: HashValue, state_root_hash: HashValue,
        event_root_hash: HashValue, gas_used: u64, status: KeptVMStatus,
    ) -> TransactionInfo {
        TransactionInfo {
            transaction_hash,
            state_root_hash,
            event_root_hash,
            gas_used,
            status,
        }
    }

    /// Returns the hash of this transaction.
    pub fn transaction_hash(&self) -> HashValue { self.transaction_hash }

    /// Returns root hash of Sparse Merkle Tree describing the world state at
    /// the end of this transaction.
    pub fn state_root_hash(&self) -> HashValue { self.state_root_hash }

    /// Returns the root hash of Merkle Accumulator storing all events emitted
    /// during this transaction.
    pub fn event_root_hash(&self) -> HashValue { self.event_root_hash }

    /// Returns the amount of gas used by this transaction.
    pub fn gas_used(&self) -> u64 { self.gas_used }

    pub fn status(&self) -> &KeptVMStatus { &self.status }
}

impl Display for TransactionInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "TransactionInfo: [txn_hash: {}, state_root_hash: {}, event_root_hash: {}, gas_used: {}, recorded_status: {:?}]",
            self.transaction_hash(), self.state_root_hash(), self.event_root_hash(), self.gas_used(), self.status(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TransactionToCommit {
    transaction: Transaction,
    events: Vec<ContractEvent>,
    gas_used: u64,
    status: KeptVMStatus,
}

impl TransactionToCommit {
    pub fn new(
        transaction: Transaction, events: Vec<ContractEvent>, gas_used: u64,
        status: KeptVMStatus,
    ) -> Self {
        TransactionToCommit {
            transaction,
            events,
            gas_used,
            status,
        }
    }

    pub fn transaction(&self) -> &Transaction { &self.transaction }

    pub fn events(&self) -> &[ContractEvent] { &self.events }

    pub fn gas_used(&self) -> u64 { self.gas_used }

    pub fn status(&self) -> &KeptVMStatus { &self.status }
}

/// `Transaction` will be the transaction type used internally in the diem node
/// to represent the transaction to be processed and persisted.
///
/// We suppress the clippy warning here as we would expect most of the
/// transaction to be user transaction.
#[allow(clippy::large_enum_variant)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    CryptoHasher,
    BCSCryptoHash,
)]
pub enum Transaction {
    /// Transaction submitted by the user. e.g: P2P payment transaction,
    /// publishing module transaction, etc.
    /// TODO: We need to rename SignedTransaction to SignedUserTransaction, as
    /// well as all the other       transaction types we had in our
    /// codebase.
    UserTransaction(SignedTransaction),

    /// Transaction that applies a WriteSet to the current storage, it's
    /// applied manually via db-bootstrapper.
    GenesisTransaction(WriteSetPayload),

    /// Transaction to update the block metadata resource at the beginning of a
    /// block.
    BlockMetadata(BlockMetadata),
}

#[derive(Deserialize)]
pub enum TransactionUnchecked {
    UserTransaction(SignedTransactionUnchecked),
    GenesisTransaction(WriteSetPayload),
    BlockMetadata(BlockMetadata),
}

impl From<TransactionUnchecked> for Transaction {
    fn from(t: TransactionUnchecked) -> Self {
        match t {
            TransactionUnchecked::UserTransaction(t) => {
                Self::UserTransaction(t.into())
            }
            TransactionUnchecked::GenesisTransaction(t) => {
                Self::GenesisTransaction(t)
            }
            TransactionUnchecked::BlockMetadata(t) => Self::BlockMetadata(t),
        }
    }
}

impl Transaction {
    pub fn as_signed_user_txn(&self) -> Result<&SignedTransaction> {
        match self {
            Transaction::UserTransaction(txn) => Ok(txn),
            _ => Err(format_err!("Not a user transaction.")),
        }
    }
}

impl TryFrom<Transaction> for SignedTransaction {
    type Error = Error;

    fn try_from(txn: Transaction) -> Result<Self> {
        match txn {
            Transaction::UserTransaction(txn) => Ok(txn),
            _ => Err(format_err!("Not a user transaction.")),
        }
    }
}
