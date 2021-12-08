// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp_derive::{RlpDecodable, RlpEncodable};

/// Auxiliary information for deferred state root, which is necessary for
/// state trees look-up. The StateRootAuxInfo should be provided by
/// consensus layer for state storage access.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    RlpEncodable,
    RlpDecodable,
    SerializeDerive,
    DeserializeDerive,
)]
#[serde(rename_all = "camelCase")]
pub struct StateRootAuxInfo {
    pub state_root_hash: H256,
}

impl StateRootAuxInfo {
    pub fn genesis_state_root_aux_info(
        genesis_state_root: &MerkleHash,
    ) -> Self {
        Default::default()
    }

    pub fn state_root_hash(&self) -> H256 { self.state_root_hash }

    pub fn next_snapshot_epoch(&self) -> H256 { todo!() }
}

/// This struct is stored as state execution result and is used to compute state
/// of children blocks.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    DeserializeDerive,
    SerializeDerive,
    RlpDecodable,
    RlpEncodable,
)]
#[serde(rename_all = "camelCase")]
pub struct StateRootWithAuxInfo {
    pub state_root: StateRoot,
    pub aux_info: StateRootAuxInfo,
}

impl StateRootWithAuxInfo {
    pub fn genesis(genesis_root: &MerkleHash) -> Self {
        let state_root = StateRoot::genesis(genesis_root);
        let genesis_state_root = state_root.compute_state_root_hash();
        Self {
            state_root,
            aux_info: StateRootAuxInfo::genesis_state_root_aux_info(
                &genesis_state_root,
            ),
        }
    }
}

impl From<(&StateRoot, &StateRootAuxInfo)> for StateRootWithAuxInfo {
    fn from(x: (&StateRoot, &StateRootAuxInfo)) -> Self {
        Self {
            state_root: x.0.clone(),
            aux_info: x.1.clone(),
        }
    }
}

/// Only used by storage benchmark due to incompatibility of rlp crate version.
pub trait StateRootWithAuxInfoToFromRlpBytes {
    fn to_rlp_bytes(&self) -> Vec<u8>;
    fn from_rlp_bytes(
        bytes: &[u8],
    ) -> Result<StateRootWithAuxInfo, DecoderError>;
}

/// Only used by storage benchmark due to incompatibility of rlp crate
/// version.
// impl StateRootWithAuxInfoToFromRlpBytes for StateRootWithAuxInfo {
//     fn to_rlp_bytes(&self) -> Vec<u8> {
//         todo!()
//     }
//
//     fn from_rlp_bytes(bytes: &[u8]) -> Result<Self, DecoderError> {
//         todo!()
//     }
// }
use super::state_root::StateRoot;
use cfx_primitives::MerkleHash;
use cfx_types::H256;
use rlp::DecoderError;
use serde_derive::{
    Deserialize as DeserializeDerive, Serialize as SerializeDerive,
};
