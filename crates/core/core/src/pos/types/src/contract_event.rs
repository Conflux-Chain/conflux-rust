// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    event::EventKey, ledger_info::LedgerInfo, proof::EventProof,
    transaction::Version,
};
use anyhow::{ensure, Result};
use diem_crypto::hash::CryptoHash;
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

/// Support versioning of the data structure.
#[derive(
    Hash,
    Clone,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    CryptoHasher,
    BCSCryptoHash,
)]
pub enum ContractEvent {
    V0(ContractEventV0),
}

impl ContractEvent {
    pub fn new(key: EventKey, event_data: Vec<u8>) -> Self {
        ContractEvent::V0(ContractEventV0::new(key, event_data))
    }
}

// Temporary hack to avoid massive changes, it won't work when new variant comes
// and needs proper dispatch at that time.
impl Deref for ContractEvent {
    type Target = ContractEventV0;

    fn deref(&self) -> &Self::Target {
        match self {
            ContractEvent::V0(event) => event,
        }
    }
}

/// Entry produced via a call to the `emit_event` builtin.
#[derive(Hash, Clone, Eq, PartialEq, Serialize, Deserialize, CryptoHasher)]
pub struct ContractEventV0 {
    /// The unique key that the event was emitted to
    key: EventKey,
    /// The data payload of the event
    #[serde(with = "serde_bytes")]
    event_data: Vec<u8>,
}

impl ContractEventV0 {
    pub fn new(key: EventKey, event_data: Vec<u8>) -> Self {
        Self { key, event_data }
    }

    pub fn key(&self) -> &EventKey { &self.key }

    pub fn event_data(&self) -> &[u8] { &self.event_data }
}

impl std::fmt::Debug for ContractEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ContractEvent {{ key: {:?}, event_data: {:?} }}",
            self.key,
            hex::encode(&self.event_data)
        )
    }
}

impl std::fmt::Display for ContractEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct EventWithProof {
    pub transaction_version: u64, // Should be `Version`
    pub event_index: u64,
    pub event: ContractEvent,
    pub proof: EventProof,
}

impl std::fmt::Display for EventWithProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventWithProof {{ \n\ttransaction_version: {}, \n\tevent_index: {}, \
             \n\tevent: {}, \n\tproof: {:?} \n}}",
            self.transaction_version, self.event_index, self.event, self.proof
        )
    }
}

impl EventWithProof {
    /// Constructor.
    pub fn new(
        transaction_version: Version, event_index: u64, event: ContractEvent,
        proof: EventProof,
    ) -> Self {
        Self {
            transaction_version,
            event_index,
            event,
            proof,
        }
    }

    /// Verifies the event with the proof, both carried by `self`.
    ///
    /// Two things are ensured if no error is raised:
    ///   1. This event exists in the ledger represented by `ledger_info`.
    ///   2. And this event has the same `event_key`, `sequence_number`,
    /// `transaction_version`, and `event_index` as indicated in the
    /// parameter list. If any of these parameter is unknown to the call
    /// site and is supposed to be informed by this struct, get it from the
    /// struct itself, such as: `event_with_proof.event.access_path()`,
    /// `event_with_proof.event_index()`, etc.
    pub fn verify(
        &self, ledger_info: &LedgerInfo, event_key: &EventKey,
        _sequence_number: u64, transaction_version: Version, event_index: u64,
    ) -> Result<()> {
        ensure!(
            self.event.key() == event_key,
            "Event key ({}) not expected ({}).",
            self.event.key(),
            *event_key,
        );
        ensure!(
            self.transaction_version == transaction_version,
            "Transaction version ({}) not expected ({}).",
            self.transaction_version,
            transaction_version,
        );
        ensure!(
            self.event_index == event_index,
            "Event index ({}) not expected ({}).",
            self.event_index,
            event_index,
        );

        self.proof.verify(
            ledger_info,
            self.event.hash(),
            transaction_version,
            event_index,
        )?;

        Ok(())
    }
}
