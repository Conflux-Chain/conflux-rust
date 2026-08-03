// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::event::EventKey;
use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};

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
