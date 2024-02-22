// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    access_path::AccessPath,
    account_address::{self, AccountAddress},
    account_config::{
        AccountResource, BalanceResource, KeyRotationCapabilityResource,
        WithdrawCapabilityResource,
    },
    account_state_blob::AccountStateBlob,
    block_info::{BlockInfo, Round},
    block_metadata::BlockMetadata,
    chain_id::ChainId,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    event::{EventHandle, EventKey},
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    on_chain_config::ValidatorSet,
    proof::TransactionListProof,
    transaction::{
        ChangeSet, Module, RawTransaction, Script, SignatureCheckedTransaction,
        SignedTransaction, Transaction, TransactionArgument,
        TransactionListWithProof, TransactionPayload, TransactionStatus,
        TransactionToCommit, Version, WriteSetPayload,
    },
    validator_config::{
        ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
        ConsensusVRFPrivateKey, ConsensusVRFPublicKey,
    },
    validator_info::ValidatorInfo,
    validator_signer::ValidatorSigner,
    vm_status::{KeptVMStatus, VMStatus},
    write_set::{WriteOp, WriteSet, WriteSetMut},
};
use diem_crypto::{bls, ec_vrf, test_utils::KeyPair, traits::*, HashValue};
use move_core_types::language_storage::TypeTag;
use proptest::{
    collection::{vec, SizeRange},
    option,
    prelude::*,
    sample::Index,
};
use proptest_derive::Arbitrary;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    iter::Iterator,
};

impl WriteOp {
    pub fn value_strategy() -> impl Strategy<Value = Self> {
        vec(any::<u8>(), 0..64).prop_map(WriteOp::Value)
    }

    pub fn deletion_strategy() -> impl Strategy<Value = Self> {
        Just(WriteOp::Deletion)
    }
}

impl Arbitrary for WriteOp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        prop_oneof![Self::deletion_strategy(), Self::value_strategy()].boxed()
    }
}

impl WriteSet {
    fn genesis_strategy() -> impl Strategy<Value = Self> {
        vec((any::<AccessPath>(), WriteOp::value_strategy()), 0..64).prop_map(
            |write_set| {
                let write_set_mut = WriteSetMut::new(write_set);
                write_set_mut
                    .freeze()
                    .expect("generated write sets should always be valid")
            },
        )
    }
}

impl Arbitrary for WriteSetPayload {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        any::<ChangeSet>().prop_map(WriteSetPayload::Direct).boxed()
    }
}

impl Arbitrary for WriteSet {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        // XXX there's no checking for repeated access paths here, nor in
        // write_set. Is that important? Not sure.
        vec((any::<AccessPath>(), any::<WriteOp>()), 0..64)
            .prop_map(|write_set| {
                let write_set_mut = WriteSetMut::new(write_set);
                write_set_mut
                    .freeze()
                    .expect("generated write sets should always be valid")
            })
            .boxed()
    }
}

impl Arbitrary for ChangeSet {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        (any::<WriteSet>(), vec(any::<ContractEvent>(), 0..10))
            .prop_map(|(ws, events)| ChangeSet::new(ws, events))
            .boxed()
    }
}

#[derive(Debug)]
struct AccountInfo {
    address: AccountAddress,
    private_key: ConsensusPrivateKey,
    public_key: ConsensusPublicKey,
    #[allow(dead_code)]
    vrf_private_key: ConsensusVRFPrivateKey,
    #[allow(dead_code)]
    vrf_public_key: ConsensusVRFPublicKey,
    sequence_number: u64,
    sent_event_handle: EventHandle,
    received_event_handle: EventHandle,
}

impl AccountInfo {
    pub fn new(
        private_key: ConsensusPrivateKey, public_key: ConsensusPublicKey,
        vrf_private_key: ConsensusVRFPrivateKey,
        vrf_public_key: ConsensusVRFPublicKey,
    ) -> Self {
        let address = account_address::from_consensus_public_key(
            &public_key,
            &vrf_public_key,
        );
        Self {
            address,
            private_key,
            public_key,
            vrf_private_key,
            vrf_public_key,
            sequence_number: 0,
            sent_event_handle: EventHandle::new_from_address(&address, 0),
            received_event_handle: EventHandle::new_from_address(&address, 1),
        }
    }
}

#[derive(Debug)]
pub struct AccountInfoUniverse {
    accounts: Vec<AccountInfo>,
    epoch: u64,
    round: Round,
    next_version: Version,
    validator_set_by_epoch: BTreeMap<u64, Vec<ValidatorSigner>>,
}

impl AccountInfoUniverse {
    fn new(
        keypairs: Vec<(
            (ConsensusPrivateKey, ConsensusPublicKey),
            (ConsensusVRFPrivateKey, ConsensusVRFPublicKey),
        )>,
        epoch: u64, round: Round, next_version: Version,
    ) -> Self {
        let accounts = keypairs
            .into_iter()
            .map(
                |(
                    (private_key, public_key),
                    (vrf_private_key, vrf_public_key),
                )| {
                    AccountInfo::new(
                        private_key,
                        public_key,
                        vrf_private_key,
                        vrf_public_key,
                    )
                },
            )
            .collect();
        let validator_set_by_epoch =
            vec![(0, Vec::new())].into_iter().collect();

        Self {
            accounts,
            epoch,
            round,
            next_version,
            validator_set_by_epoch,
        }
    }

    fn get_account_info(&self, account_index: Index) -> &AccountInfo {
        account_index.get(&self.accounts)
    }

    fn get_account_infos_dedup(
        &self, account_indices: &[Index],
    ) -> Vec<&AccountInfo> {
        account_indices
            .iter()
            .map(|idx| idx.index(self.accounts.len()))
            .collect::<BTreeSet<_>>()
            .iter()
            .map(|idx| &self.accounts[*idx])
            .collect()
    }

    fn get_account_info_mut(
        &mut self, account_index: Index,
    ) -> &mut AccountInfo {
        account_index.get_mut(self.accounts.as_mut_slice())
    }

    fn get_and_bump_round(&mut self) -> Round {
        let round = self.round;
        self.round += 1;
        round
    }

    fn bump_and_get_version(&mut self, block_size: usize) -> Version {
        self.next_version += block_size as u64;
        self.next_version - 1
    }

    fn get_epoch(&self) -> u64 { self.epoch }

    fn get_and_bump_epoch(&mut self) -> u64 {
        let epoch = self.epoch;
        self.epoch += 1;
        epoch
    }

    pub fn get_validator_set(&self, epoch: u64) -> &[ValidatorSigner] {
        &self.validator_set_by_epoch[&epoch]
    }

    fn set_validator_set(
        &mut self, epoch: u64, validator_set: Vec<ValidatorSigner>,
    ) {
        self.validator_set_by_epoch.insert(epoch, validator_set);
    }
}

impl Arbitrary for AccountInfoUniverse {
    type Parameters = usize;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(num_accounts: Self::Parameters) -> Self::Strategy {
        vec(
            (bls::keypair_strategy(), ec_vrf::keypair_strategy()),
            num_accounts,
        )
        .prop_map(|kps| {
            let kps: Vec<_> = kps
                .into_iter()
                .map(|k| {
                    (
                        (k.0.private_key, k.0.public_key),
                        (k.1.private_key, k.1.public_key),
                    )
                })
                .collect();
            AccountInfoUniverse::new(
                kps, /* epoch = */ 0, /* round = */ 0,
                /* next_version = */ 0,
            )
        })
        .boxed()
    }

    fn arbitrary() -> Self::Strategy {
        unimplemented!("Size of the universe must be provided explicitly (use any_with instead).")
    }
}

#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
pub struct RawTransactionGen {
    payload: TransactionPayload,
    max_gas_amount: u64,
    gas_unit_price: u64,
    gas_currency_code: String,
    expiration_time_secs: u64,
}

impl RawTransactionGen {
    pub fn materialize(
        self, sender_index: Index, universe: &mut AccountInfoUniverse,
    ) -> RawTransaction {
        let sender_info = universe.get_account_info_mut(sender_index);

        sender_info.sequence_number += 1;

        new_raw_transaction(
            sender_info.address,
            self.payload,
            self.expiration_time_secs,
        )
    }
}

impl RawTransaction {
    fn strategy_impl(
        address_strategy: impl Strategy<Value = AccountAddress>,
        payload_strategy: impl Strategy<Value = TransactionPayload>,
    ) -> impl Strategy<Value = Self> {
        // XXX what other constraints do these need to obey?
        (address_strategy, payload_strategy, any::<u64>()).prop_map(
            |(sender, payload, expiration_time_secs)| {
                new_raw_transaction(sender, payload, expiration_time_secs)
            },
        )
    }
}

fn new_raw_transaction(
    sender: AccountAddress, payload: TransactionPayload,
    expiration_time_secs: u64,
) -> RawTransaction {
    let chain_id = ChainId::test();
    match payload {
        TransactionPayload::Module(module) => RawTransaction::new_module(
            sender,
            module,
            expiration_time_secs,
            chain_id,
        ),
        TransactionPayload::Script(script) => RawTransaction::new_script(
            sender,
            script,
            expiration_time_secs,
            chain_id,
        ),
        TransactionPayload::ScriptFunction(script_fn) => {
            RawTransaction::new_script_function(
                sender,
                script_fn,
                expiration_time_secs,
                chain_id,
            )
        }
        TransactionPayload::WriteSet(WriteSetPayload::Direct(write_set)) => {
            // It's a bit unfortunate that max_gas_amount etc is generated but
            // not used, but it isn't a huge deal.
            RawTransaction::new_change_set(sender, write_set, chain_id)
        }
        TransactionPayload::WriteSet(WriteSetPayload::Script {
            execute_as: signer,
            script,
        }) => RawTransaction::new_writeset_script(
            sender, script, signer, chain_id,
        ),
        TransactionPayload::Election(election_payload) => {
            RawTransaction::new_election(sender, election_payload, chain_id)
        }
        TransactionPayload::Retire(retire_payload) => {
            RawTransaction::new_retire(sender, retire_payload)
        }
        TransactionPayload::Register(register_payload) => RawTransaction::new(
            sender,
            TransactionPayload::Register(register_payload),
            0,
            chain_id,
        ),
        TransactionPayload::UpdateVotingPower(update_voting_power_payload) => {
            RawTransaction::new(
                sender,
                TransactionPayload::UpdateVotingPower(
                    update_voting_power_payload,
                ),
                0,
                chain_id,
            )
        }
        TransactionPayload::PivotDecision(pivot_decision) => {
            RawTransaction::new_pivot_decision(sender, pivot_decision, chain_id)
        }
        TransactionPayload::Dispute(dispute_payload) => {
            RawTransaction::new_dispute(sender, dispute_payload)
        }
    }
}

impl Arbitrary for RawTransaction {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        Self::strategy_impl(
            any::<AccountAddress>(),
            any::<TransactionPayload>(),
        )
        .boxed()
    }
}

impl SignatureCheckedTransaction {
    pub fn genesis_strategy(
        keypair_strategy: impl Strategy<
            Value = KeyPair<ConsensusPrivateKey, ConsensusPublicKey>,
        >,
        vrf_keypair_strategy: impl Strategy<
            Value = KeyPair<ConsensusVRFPrivateKey, ConsensusVRFPublicKey>,
        >,
    ) -> impl Strategy<Value = Self> {
        Self::strategy_impl(
            keypair_strategy,
            vrf_keypair_strategy,
            TransactionPayload::genesis_strategy(),
        )
    }

    fn strategy_impl(
        keypair_strategy: impl Strategy<
            Value = KeyPair<ConsensusPrivateKey, ConsensusPublicKey>,
        >,
        vrf_keypair_strategy: impl Strategy<
            Value = KeyPair<ConsensusVRFPrivateKey, ConsensusVRFPublicKey>,
        >,
        payload_strategy: impl Strategy<Value = TransactionPayload>,
    ) -> impl Strategy<Value = Self> {
        (keypair_strategy, vrf_keypair_strategy, payload_strategy)
            .prop_flat_map(|(keypair, vrf_keypair, payload)| {
                let address = account_address::from_consensus_public_key(
                    &keypair.public_key,
                    &vrf_keypair.public_key,
                );
                (
                    Just(keypair),
                    RawTransaction::strategy_impl(Just(address), Just(payload)),
                )
            })
            .prop_flat_map(|(keypair, raw_txn)| {
                prop_oneof![Just(
                    raw_txn
                        .clone()
                        .sign(&keypair.private_key)
                        .expect("signing should always work")
                )]
            })
    }
}

#[derive(Arbitrary, Debug)]
pub struct SignatureCheckedTransactionGen {
    raw_transaction_gen: RawTransactionGen,
}

impl SignatureCheckedTransactionGen {
    pub fn materialize(
        self, sender_index: Index, universe: &mut AccountInfoUniverse,
    ) -> SignatureCheckedTransaction {
        let raw_txn =
            self.raw_transaction_gen.materialize(sender_index, universe);
        let account_info = universe.get_account_info(sender_index);
        raw_txn
            .sign(&account_info.private_key)
            .expect("Signing raw transaction should work.")
    }
}

impl Arbitrary for SignatureCheckedTransaction {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        Self::strategy_impl(
            bls::keypair_strategy(),
            ec_vrf::keypair_strategy(),
            any::<TransactionPayload>(),
        )
        .boxed()
    }
}

/// This `Arbitrary` impl only generates valid signed transactions. TODO: maybe
/// add invalid ones?
impl Arbitrary for SignedTransaction {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        any::<SignatureCheckedTransaction>()
            .prop_map(|txn| txn.into_inner())
            .boxed()
    }
}

impl TransactionPayload {
    pub fn script_strategy() -> impl Strategy<Value = Self> {
        any::<Script>().prop_map(TransactionPayload::Script)
    }

    pub fn module_strategy() -> impl Strategy<Value = Self> {
        any::<Module>().prop_map(TransactionPayload::Module)
    }

    pub fn write_set_strategy() -> impl Strategy<Value = Self> {
        any::<WriteSet>().prop_map(|ws| {
            TransactionPayload::WriteSet(WriteSetPayload::Direct(
                ChangeSet::new(ws, vec![]),
            ))
        })
    }

    /// Similar to `write_set_strategy` except generates a valid write set for
    /// the genesis block.
    pub fn genesis_strategy() -> impl Strategy<Value = Self> {
        WriteSet::genesis_strategy().prop_map(|ws| {
            TransactionPayload::WriteSet(WriteSetPayload::Direct(
                ChangeSet::new(ws, vec![]),
            ))
        })
    }
}

prop_compose! {
    fn arb_transaction_status()(vm_status in any::<VMStatus>()) -> TransactionStatus {
        vm_status.into()
    }
}

prop_compose! {
    fn arb_pubkey()(keypair in bls::keypair_strategy(), vrf_keypair in ec_vrf::keypair_strategy()) -> AccountAddress {
        account_address::from_consensus_public_key(&keypair.public_key, &vrf_keypair.public_key)
    }
}

impl Arbitrary for TransactionStatus {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_transaction_status().boxed()
    }
}

impl Arbitrary for TransactionPayload {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        // Most transactions in practice will be programs, but other parts of
        // the system should at least not choke on write set strategies
        // so introduce them with decent probability. The figures below
        // are probability weights.
        prop_oneof![
            4 => Self::script_strategy(),
            1 => Self::module_strategy(),
            1 => Self::write_set_strategy(),
        ]
        .boxed()
    }
}

impl Arbitrary for Script {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        // XXX This should eventually be an actually valid program, maybe?
        // The vector sizes are picked out of thin air.
        (
            vec(any::<u8>(), 0..100),
            vec(any::<TypeTag>(), 0..4),
            vec(any::<TransactionArgument>(), 0..10),
        )
            .prop_map(|(code, ty_args, args)| Script::new(code, ty_args, args))
            .boxed()
    }
}

impl Arbitrary for Module {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        // XXX How should we generate random modules?
        // The vector sizes are picked out of thin air.
        vec(any::<u8>(), 0..100).prop_map(Module::new).boxed()
    }
}

prop_compose! {
    fn arb_validator_signature_for_ledger_info(ledger_info: LedgerInfo)(
        ledger_info in Just(ledger_info),
        keypair in bls::keypair_strategy(),
        vrf_keypair in ec_vrf::keypair_strategy(),
    ) -> (AccountAddress, ConsensusSignature) {
        let signature = keypair.private_key.sign(&ledger_info);
        (account_address::from_consensus_public_key(&keypair.public_key, &vrf_keypair.public_key), signature)
    }
}

impl Arbitrary for LedgerInfoWithSignatures {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(
        num_validators_range: Self::Parameters,
    ) -> Self::Strategy {
        (any::<LedgerInfo>(), Just(num_validators_range))
            .prop_flat_map(|(ledger_info, num_validators_range)| {
                (
                    Just(ledger_info.clone()),
                    prop::collection::vec(
                        arb_validator_signature_for_ledger_info(ledger_info),
                        num_validators_range,
                    ),
                )
            })
            .prop_map(|(ledger_info, signatures)| {
                LedgerInfoWithSignatures::new(
                    ledger_info,
                    signatures.into_iter().collect(),
                )
            })
            .boxed()
    }
}

#[derive(Arbitrary, Debug)]
pub struct ContractEventGen {
    payload: Vec<u8>,
    use_sent_key: bool,
}

impl ContractEventGen {
    pub fn materialize(
        self, account_index: Index, universe: &mut AccountInfoUniverse,
    ) -> ContractEvent {
        let account_info = universe.get_account_info_mut(account_index);
        let event_handle = if self.use_sent_key {
            &mut account_info.sent_event_handle
        } else {
            &mut account_info.received_event_handle
        };
        *event_handle.count_mut() += 1;
        let event_key = event_handle.key();

        ContractEvent::new(*event_key, self.payload)
    }
}

#[derive(Arbitrary, Debug)]
pub struct AccountResourceGen {
    withdrawal_capability: Option<WithdrawCapabilityResource>,
    key_rotation_capability: Option<KeyRotationCapabilityResource>,
}

impl AccountResourceGen {
    pub fn materialize(
        self, account_index: Index, universe: &AccountInfoUniverse,
    ) -> AccountResource {
        let account_info = universe.get_account_info(account_index);

        AccountResource::new(
            account_info.sequence_number,
            account_info.public_key.to_bytes().to_vec(),
            self.withdrawal_capability,
            self.key_rotation_capability,
            account_info.sent_event_handle.clone(),
            account_info.received_event_handle.clone(),
        )
    }
}

#[derive(Arbitrary, Debug)]
pub struct BalanceResourceGen {
    coin: u64,
}

impl BalanceResourceGen {
    pub fn materialize(self) -> BalanceResource {
        BalanceResource::new(self.coin)
    }
}

#[derive(Arbitrary, Debug)]
pub struct AccountStateBlobGen {
    account_resource_gen: AccountResourceGen,
    balance_resource_gen: BalanceResourceGen,
}

impl AccountStateBlobGen {
    pub fn materialize(
        self, account_index: Index, universe: &AccountInfoUniverse,
    ) -> AccountStateBlob {
        let account_resource = self
            .account_resource_gen
            .materialize(account_index, universe);
        let balance_resource = self.balance_resource_gen.materialize();
        AccountStateBlob::try_from((&account_resource, &balance_resource))
            .unwrap()
    }
}

impl EventHandle {
    pub fn strategy_impl(
        event_key_strategy: impl Strategy<Value = EventKey>,
    ) -> impl Strategy<Value = Self> {
        // We only generate small counters so that it won't overflow.
        (event_key_strategy, 0..std::u64::MAX / 2).prop_map(
            |(event_key, counter)| EventHandle::new(event_key, counter),
        )
    }
}

impl Arbitrary for EventHandle {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        EventHandle::strategy_impl(any::<EventKey>()).boxed()
    }
}

impl ContractEvent {
    pub fn strategy_impl(
        event_key_strategy: impl Strategy<Value = EventKey>,
    ) -> impl Strategy<Value = Self> {
        (event_key_strategy, vec(any::<u8>(), 1..10)).prop_map(
            |(event_key, event_data)| ContractEvent::new(event_key, event_data),
        )
    }
}

impl Arbitrary for ContractEvent {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        ContractEvent::strategy_impl(any::<EventKey>()).boxed()
    }
}

impl Arbitrary for TransactionToCommit {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any_with::<AccountInfoUniverse>(1),
            any::<TransactionToCommitGen>(),
        )
            .prop_map(|(mut universe, gen)| gen.materialize(&mut universe))
            .boxed()
    }
}

/// Represents information already determined for generating a
/// `TransactionToCommit`, along with to be determined information that needs to
/// settle upon `materialize()`, for example a to be determined account can be
/// represented by an `Index` which will be materialized to an entry in
/// the `AccountInfoUniverse`.
///
/// See `TransactionToCommitGen::materialize()` and supporting types.
#[derive(Debug)]
pub struct TransactionToCommitGen {
    /// Transaction sender and the transaction itself.
    transaction_gen: (Index, SignatureCheckedTransactionGen),
    /// Events: account and event content.
    event_gens: Vec<(Index, ContractEventGen)>,
    /// State updates: account and the blob.
    /// N.B. the transaction sender and event owners must be updated to reflect
    /// information such as sequence numbers so that test data generated
    /// through this is more realistic and logical.
    account_state_gens: Vec<(Index, AccountStateBlobGen)>,
    /// Gas used.
    gas_used: u64,
    /// Transaction status
    status: KeptVMStatus,
}

impl TransactionToCommitGen {
    /// Materialize considering current states in the universe.
    pub fn materialize(
        self, universe: &mut AccountInfoUniverse,
    ) -> TransactionToCommit {
        let (sender_index, txn_gen) = self.transaction_gen;
        let transaction =
            txn_gen.materialize(sender_index, universe).into_inner();

        let events = self
            .event_gens
            .into_iter()
            .map(|(index, event_gen)| event_gen.materialize(index, universe))
            .collect();
        // Account states must be materialized last, to reflect the latest
        // account and event sequence numbers.
        let account_states = self
            .account_state_gens
            .into_iter()
            .map(|(index, blob_gen)| {
                (
                    universe.get_account_info(index).address,
                    blob_gen.materialize(index, universe),
                )
            })
            .collect();

        TransactionToCommit::new(
            Transaction::UserTransaction(transaction),
            account_states,
            events,
            self.gas_used,
            self.status,
        )
    }
}

impl Arbitrary for TransactionToCommitGen {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            (
                any::<Index>(),
                any::<AccountStateBlobGen>(),
                any::<SignatureCheckedTransactionGen>(),
            ),
            vec(
                (
                    any::<Index>(),
                    any::<AccountStateBlobGen>(),
                    any::<ContractEventGen>(),
                ),
                0..=2,
            ),
            vec((any::<Index>(), any::<AccountStateBlobGen>()), 0..=1),
            any::<u64>(),
            any::<KeptVMStatus>(),
        )
            .prop_map(
                |(
                    sender,
                    event_emitters,
                    mut touched_accounts,
                    gas_used,
                    status,
                )| {
                    // To reflect change of account/event sequence numbers, txn
                    // sender account and event emitter
                    // accounts must be updated.
                    let (sender_index, sender_blob_gen, txn_gen) = sender;
                    touched_accounts.push((sender_index, sender_blob_gen));

                    let mut event_gens = Vec::new();
                    for (index, blob_gen, event_gen) in event_emitters {
                        touched_accounts.push((index, blob_gen));
                        event_gens.push((index, event_gen));
                    }

                    Self {
                        transaction_gen: (sender_index, txn_gen),
                        event_gens,
                        account_state_gens: touched_accounts,
                        gas_used,
                        status,
                    }
                },
            )
            .boxed()
    }
}

fn arb_transaction_list_with_proof(
) -> impl Strategy<Value = TransactionListWithProof> {
    (
        vec(
            (
                any::<SignedTransaction>(),
                vec(any::<ContractEvent>(), 0..10),
            ),
            0..10,
        ),
        any::<TransactionListProof>(),
    )
        .prop_flat_map(|(transaction_and_events, proof)| {
            let transactions: Vec<_> = transaction_and_events
                .clone()
                .into_iter()
                .map(|(transaction, _event)| {
                    Transaction::UserTransaction(transaction)
                })
                .collect();
            let events: Vec<_> = transaction_and_events
                .into_iter()
                .map(|(_transaction, event)| event)
                .collect();

            (
                Just(transactions.clone()),
                option::of(Just(events)),
                if transactions.is_empty() {
                    Just(None).boxed()
                } else {
                    any::<Version>().prop_map(Some).boxed()
                },
                Just(proof),
            )
        })
        .prop_map(|(transactions, events, first_txn_version, proof)| {
            TransactionListWithProof::new(
                transactions,
                events,
                first_txn_version,
                proof,
            )
        })
}

impl Arbitrary for TransactionListWithProof {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        arb_transaction_list_with_proof().boxed()
    }
}

impl Arbitrary for BlockMetadata {
    type Parameters = SizeRange;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(
        num_validators_range: Self::Parameters,
    ) -> Self::Strategy {
        let addr_strategy =
            (Just(num_validators_range)).prop_flat_map(|num_validator_range| {
                prop::collection::vec(arb_pubkey(), num_validator_range)
            });
        (
            any::<HashValue>(),
            any::<u64>(),
            any::<u64>(),
            addr_strategy,
            any::<AccountAddress>(),
        )
            .prop_map(|(id, round, timestamp, addresses, proposer)| {
                BlockMetadata::new(id, round, timestamp, addresses, proposer)
            })
            .boxed()
    }
}

#[derive(Debug)]
struct ValidatorSetGen {
    validators: Vec<Index>,
}

impl ValidatorSetGen {
    pub fn materialize(
        self, universe: &mut AccountInfoUniverse,
    ) -> Vec<ValidatorSigner> {
        universe
            .get_account_infos_dedup(&self.validators)
            .iter()
            .map(|account| {
                ValidatorSigner::new(
                    account.address,
                    account.private_key.clone(),
                    None,
                )
            })
            .collect()
    }
}

impl Arbitrary for ValidatorSetGen {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        vec(any::<Index>(), 3)
            .prop_map(|validators| Self { validators })
            .boxed()
    }
}

#[derive(Debug)]
pub struct BlockInfoGen {
    id: HashValue,
    executed_state_id: HashValue,
    timestamp_usecs: u64,
    new_epoch: bool,
    validator_set_gen: ValidatorSetGen,
}

impl BlockInfoGen {
    pub fn materialize(
        self, universe: &mut AccountInfoUniverse, block_size: usize,
    ) -> BlockInfo {
        assert!(block_size > 0, "No empty blocks are allowed.");

        let current_epoch = universe.get_epoch();
        // The first LedgerInfo should always carry a validator set.
        let next_epoch_state = if current_epoch == 0 || self.new_epoch {
            let next_validator_set =
                self.validator_set_gen.materialize(universe);
            let next_validator_infos = next_validator_set
                .iter()
                .map(|signer| {
                    ValidatorInfo::new_with_test_network_keys(
                        signer.author(),
                        signer.public_key(),
                        None,
                        1, /* consensus_voting_power */
                    )
                })
                .collect();
            let next_epoch_state = EpochState::new(
                current_epoch + 1,
                (&ValidatorSet::new(next_validator_infos)).into(),
                vec![],
            );

            universe.get_and_bump_epoch();
            universe.set_validator_set(current_epoch + 1, next_validator_set);
            Some(next_epoch_state)
        } else {
            None
        };

        BlockInfo::new(
            current_epoch,
            universe.get_and_bump_round(),
            self.id,
            self.executed_state_id,
            universe.bump_and_get_version(block_size),
            self.timestamp_usecs,
            next_epoch_state,
            None,
        )
    }
}

impl Arbitrary for BlockInfoGen {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        // A small percent of them generate epoch changes.
        (
            any::<HashValue>(),
            any::<HashValue>(),
            any::<u64>(),
            prop_oneof![1 => Just(true), 3 => Just(false)],
            any::<ValidatorSetGen>(),
        )
            .prop_map(
                |(
                    id,
                    executed_state_id,
                    timestamp_usecs,
                    new_epoch,
                    validator_set_gen,
                )| Self {
                    id,
                    executed_state_id,
                    timestamp_usecs,
                    new_epoch,
                    validator_set_gen,
                },
            )
            .boxed()
    }
}

#[derive(Arbitrary, Debug)]
pub struct LedgerInfoGen {
    commit_info_gen: BlockInfoGen,
    consensus_data_hash: HashValue,
}

impl LedgerInfoGen {
    pub fn materialize(
        self, universe: &mut AccountInfoUniverse, block_size: usize,
    ) -> LedgerInfo {
        LedgerInfo::new(
            self.commit_info_gen.materialize(universe, block_size),
            self.consensus_data_hash,
        )
    }
}

#[derive(Debug)]
pub struct LedgerInfoWithSignaturesGen {
    ledger_info_gen: LedgerInfoGen,
}

impl Arbitrary for LedgerInfoWithSignaturesGen {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<LedgerInfoGen>()
            .prop_map(|ledger_info_gen| LedgerInfoWithSignaturesGen {
                ledger_info_gen,
            })
            .boxed()
    }
}

impl LedgerInfoWithSignaturesGen {
    pub fn materialize(
        self, universe: &mut AccountInfoUniverse, block_size: usize,
    ) -> LedgerInfoWithSignatures {
        let ledger_info =
            self.ledger_info_gen.materialize(universe, block_size);
        let signatures = universe
            .get_validator_set(ledger_info.epoch())
            .iter()
            .map(|signer| (signer.author(), signer.sign(&ledger_info)))
            .collect();

        LedgerInfoWithSignatures::new(ledger_info, signatures)
    }
}

// This function generates an arbitrary serde_json::Value.
pub fn arb_json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<f64>().prop_map(|n| serde_json::json!(n)),
        any::<String>().prop_map(Value::String),
    ];

    leaf.prop_recursive(
        10,  // 10 levels deep
        256, // Maximum size of 256 nodes
        10,  // Up to 10 items per collection
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..10)
                    .prop_map(Value::Array),
                prop::collection::hash_map(any::<String>(), inner, 0..10)
                    .prop_map(|map| serde_json::json!(map)),
            ]
        },
    )
}
