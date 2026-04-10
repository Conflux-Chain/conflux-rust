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
    validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
    PeerId,
};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub test: Option<SafetyRulesTestConfig>,
    pub export_consensus_key: bool,
    pub enable_cached_safety_data: bool,

    pub vrf_private_key: Option<ConfigKey<ConsensusVRFPrivateKey>>,
    pub vrf_proposal_threshold: U256,
}

impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: SecureBackend::OnDiskStorage(Default::default()),
            logger: LoggerConfig::default(),
            test: None,
            export_consensus_key: false,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SafetyRulesTestConfig {
    pub author: PeerId,
    pub consensus_key: Option<ConfigKey<ConsensusPrivateKey>>,
    pub execution_key: Option<ConfigKey<ConsensusPrivateKey>>,
}

impl SafetyRulesTestConfig {
    pub fn new(author: PeerId) -> Self {
        Self {
            author,
            consensus_key: None,
            execution_key: None,
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
