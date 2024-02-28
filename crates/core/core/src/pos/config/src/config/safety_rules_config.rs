// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    config::{LoggerConfig, SecureBackend},
    keys::ConfigKey,
};
use cfx_types::U256;
use diem_crypto::Uniform;
use diem_types::{
    network_address::NetworkAddress,
    validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
    waypoint::Waypoint,
    PeerId,
};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    pub verify_vote_proposal_signature: bool,
    pub export_consensus_key: bool,
    // Read/Write/Connect networking operation timeout in milliseconds.
    pub network_timeout_ms: u64,
    pub enable_cached_safety_data: bool,

    pub vrf_private_key: Option<ConfigKey<ConsensusVRFPrivateKey>>,
    pub vrf_proposal_threshold: U256,
}

impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: SecureBackend::OnDiskStorage(Default::default()),
            logger: LoggerConfig::default(),
            service: SafetyRulesService::Thread,
            test: None,
            verify_vote_proposal_signature: true,
            export_consensus_key: false,
            // Default value of 30 seconds for a timeout
            network_timeout_ms: 30_000,
            enable_cached_safety_data: true,
            vrf_private_key: None,
            vrf_proposal_threshold: U256::MAX,
        }
    }
}

impl SafetyRulesConfig {
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        if let SecureBackend::OnDiskStorage(backend) = &mut self.backend {
            backend.set_data_dir(data_dir);
        }
    }
}

/// Defines how safety rules should be executed
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SafetyRulesService {
    /// This runs safety rules in the same thread as event processor
    Local,
    /// This is the production, separate service approach
    Process(RemoteService),
    /// This runs safety rules in the same thread as event processor but data
    /// is passed through the light weight RPC (serializer)
    Serializer,
    /// This creates a separate thread to run safety rules, it is similar to a
    /// fork / exec style
    Thread,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteService {
    pub server_address: NetworkAddress,
}

impl RemoteService {
    pub fn server_address(&self) -> SocketAddr {
        self.server_address
            .to_socket_addrs()
            .expect("server_address invalid")
            .next()
            .expect("server_address invalid")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SafetyRulesTestConfig {
    pub author: PeerId,
    pub consensus_key: Option<ConfigKey<ConsensusPrivateKey>>,
    pub execution_key: Option<ConfigKey<ConsensusPrivateKey>>,
    pub waypoint: Option<Waypoint>,
}

impl SafetyRulesTestConfig {
    pub fn new(author: PeerId) -> Self {
        Self {
            author,
            consensus_key: None,
            execution_key: None,
            waypoint: None,
        }
    }

    pub fn consensus_key(&mut self, key: ConsensusPrivateKey) {
        self.consensus_key = Some(ConfigKey::new(key));
    }

    pub fn execution_key(&mut self, key: ConsensusPrivateKey) {
        self.execution_key = Some(ConfigKey::new(key));
    }

    pub fn random_consensus_key(&mut self, rng: &mut StdRng) {
        let privkey = ConsensusPrivateKey::generate(rng);
        self.consensus_key =
            Some(ConfigKey::<ConsensusPrivateKey>::new(privkey));
    }

    pub fn random_execution_key(&mut self, rng: &mut StdRng) {
        let privkey = ConsensusPrivateKey::generate(rng);
        self.execution_key =
            Some(ConfigKey::<ConsensusPrivateKey>::new(privkey));
    }
}
