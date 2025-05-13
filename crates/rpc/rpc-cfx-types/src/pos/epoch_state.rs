use cfx_rpc_primitives::Bytes;
use cfx_types::{H256, U64};
use diem_crypto::ValidCryptoMaterial;
use diem_types::{
    epoch_state::EpochState as PrimitiveEpochState,
    validator_verifier::{
        ValidatorConsensusInfo as PrimitiveValidatorConsensusInfo,
        ValidatorVerifier as PrimitiveValidatorVerifier,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochState {
    epoch: U64,

    verifier: ValidatorVerifier,

    vrf_seed: Bytes,
}

impl From<&PrimitiveEpochState> for EpochState {
    fn from(value: &PrimitiveEpochState) -> Self {
        Self {
            epoch: value.epoch.into(),
            verifier: value.verifier().into(),
            vrf_seed: value.vrf_seed.clone().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorVerifier {
    /// An ordered map of each validator's on-chain account address to its
    /// pubkeys and voting power.
    address_to_validator_info: BTreeMap<H256, ValidatorConsensusInfo>,
    /// The minimum voting power required to achieve a quorum
    quorum_voting_power: U64,
    /// Total voting power of all validators (cached from
    /// address_to_validator_info)
    total_voting_power: U64,
}

impl From<&PrimitiveValidatorVerifier> for ValidatorVerifier {
    fn from(value: &PrimitiveValidatorVerifier) -> Self {
        Self {
            address_to_validator_info: value
                .address_to_validator_info()
                .iter()
                .map(|(k, v)| (k.to_u8().into(), v.into()))
                .collect(),
            quorum_voting_power: value.quorum_voting_power().into(),
            total_voting_power: value.total_voting_power().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorConsensusInfo {
    // We always vote for our local EpochState, and EpochState is included in
    // the voted hash. Thus, if a malicious pubkey is provided here, its
    // LedgerInfo won't get a QC.
    // #[serde(deserialize_with = "deserialize_bls_public_key_unchecked")]
    /// Compressed BLS public key in 48 bytes for BCS serialization.
    public_key: Bytes,
    /// None if we do not need VRF.
    vrf_public_key: Option<Bytes>,
    voting_power: U64,
}

impl From<&PrimitiveValidatorConsensusInfo> for ValidatorConsensusInfo {
    fn from(value: &PrimitiveValidatorConsensusInfo) -> Self {
        Self {
            public_key: value
                .public_key()
                .clone()
                .raw()
                .as_affine()
                .to_compressed()
                .to_vec()
                .into(),
            vrf_public_key: value
                .vrf_public_key()
                .clone()
                .map(|k| k.to_bytes().into()),
            voting_power: value.voting_power().into(),
        }
    }
}
