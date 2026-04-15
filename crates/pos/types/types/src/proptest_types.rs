// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    account_address::{self, AccountAddress},
    block_info::{BlockInfo, Round},
    block_metadata::BlockMetadata,
    chain_id::ChainId,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    event::{EventHandle, EventKey},
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    on_chain_config::ValidatorSet,
    transaction::{
        RawTransaction, SignatureCheckedTransaction, SignedTransaction,
        Transaction, TransactionPayload, TransactionStatus,
        TransactionToCommit, Version,
    },
    validator_config::{
        ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
        ConsensusVRFPrivateKey, ConsensusVRFPublicKey,
    },
    validator_info::ValidatorInfo,
    validator_signer::ValidatorSigner,
    vm_status::{KeptVMStatus, VMStatus},
};
use diem_crypto::{bls, ec_vrf, test_utils::KeyPair, traits::*, HashValue};
use proptest::{
    collection::{vec, SizeRange},
    prelude::*,
    sample::Index,
};
use proptest_derive::Arbitrary;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    iter::Iterator,
};

#[derive(Debug)]
struct AccountInfo {
    address: AccountAddress,
    private_key: ConsensusPrivateKey,
    sequence_number: u64,
    sent_event_handle: EventHandle,
    received_event_handle: EventHandle,
}

impl AccountInfo {
    pub fn new(
        private_key: ConsensusPrivateKey, public_key: ConsensusPublicKey,
        _vrf_private_key: ConsensusVRFPrivateKey,
        vrf_public_key: ConsensusVRFPublicKey,
    ) -> Self {
        let address = account_address::from_consensus_public_key(
            &public_key,
            &vrf_public_key,
        );
        Self {
            address,
            private_key,
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
    RawTransaction::new(sender, payload, expiration_time_secs, chain_id)
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

    // Only the legacy placeholder variants are generated: the active
    // Conflux PoS payloads (Election, Retire, …) lack `Arbitrary` impls.
    // Covering all four `_Legacy*` variants at least exercises the BCS
    // variant-index stability they exist to protect.
    fn arbitrary_with(_args: ()) -> Self::Strategy {
        prop_oneof![
            Just(TransactionPayload::_LegacyWriteSet),
            Just(TransactionPayload::_LegacyScript),
            Just(TransactionPayload::_LegacyModule),
            Just(TransactionPayload::_LegacyScriptFunction),
        ]
        .boxed()
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

        TransactionToCommit::new(
            Transaction::UserTransaction(transaction),
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
            (any::<Index>(), any::<SignatureCheckedTransactionGen>()),
            vec((any::<Index>(), any::<ContractEventGen>()), 0..=2),
            any::<u64>(),
            any::<KeptVMStatus>(),
        )
            .prop_map(|(sender, event_emitters, gas_used, status)| {
                let (sender_index, txn_gen) = sender;

                let mut event_gens = Vec::new();
                for (index, event_gen) in event_emitters {
                    event_gens.push((index, event_gen));
                }

                Self {
                    transaction_gen: (sender_index, txn_gen),
                    event_gens,
                    gas_used,
                    status,
                }
            })
            .boxed()
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
