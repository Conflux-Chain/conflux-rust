// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_crypto::{
    bls::{BLSPrivateKey, BLSPublicKey, BLSSignature},
    ec_vrf::{EcVrfPrivateKey, EcVrfProof, EcVrfPublicKey},
    multi_bls::{MultiBLSPrivateKey, MultiBLSPublicKey, MultiBLSSignature},
};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct ValidatorConfig {
    pub consensus_public_key: ConsensusPublicKey,
    /// None if the leader election does not need VRF.
    pub vrf_public_key: Option<ConsensusVRFPublicKey>,
    /// This is a bcs serialized validator network address blob
    pub validator_network_addresses: Vec<u8>,
    /// This is an bcs serialized `Vec<NetworkAddress>`
    pub fullnode_network_addresses: Vec<u8>,
}

impl ValidatorConfig {
    pub fn new(
        consensus_public_key: ConsensusPublicKey,
        vrf_public_key: Option<ConsensusVRFPublicKey>,
        validator_network_addresses: Vec<u8>,
        fullnode_network_addresses: Vec<u8>,
    ) -> Self {
        ValidatorConfig {
            consensus_public_key,
            vrf_public_key,
            validator_network_addresses,
            fullnode_network_addresses,
        }
    }
}

// TODO(lpl): Put this in a proper place.
pub type ConsensusPublicKey = BLSPublicKey;
pub type ConsensusPrivateKey = BLSPrivateKey;
pub type ConsensusSignature = BLSSignature;
pub type ConsensusVRFPublicKey = EcVrfPublicKey;
pub type ConsensusVRFPrivateKey = EcVrfPrivateKey;
pub type ConsensusVRFProof = EcVrfProof;
pub type MultiConsensusPublicKey = MultiBLSPublicKey;
pub type MultiConsensusPrivateKey = MultiBLSPrivateKey;
pub type MultiConsensusSignature = MultiBLSSignature;
