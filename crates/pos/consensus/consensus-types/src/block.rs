// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data::{BlockData, BlockDataUnchecked, BlockType},
    common::{Author, Payload, Round},
    quorum_cert::QuorumCert,
};
use anyhow::{bail, ensure, format_err};
use diem_crypto::{hash::CryptoHash, HashValue};
use diem_infallible::duration_since_epoch;
use diem_types::{
    account_address::AccountAddress,
    block_info::{BlockInfo, PivotBlockDecision},
    block_metadata::BlockMetadata,
    epoch_state::EpochState,
    ledger_info::LedgerInfo,
    transaction::Version,
    validator_config::{ConsensusSignature, ConsensusVRFProof},
    validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use mirai_annotations::debug_checked_verify_eq;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{self, Display, Formatter};

#[path = "block_test_utils.rs"]
#[cfg(any(test, feature = "fuzzing"))]
pub mod block_test_utils;

#[cfg(test)]
#[path = "block_test.rs"]
pub mod block_test;

#[derive(Serialize, Clone, PartialEq, Eq)]
/// Block has the core data of a consensus block that should be persistent when
/// necessary. Each block must know the id of its parent and keep the
/// QuorurmCertificate to that parent.
pub struct Block {
    /// This block's id as a hash value, it is generated at call time
    #[serde(skip)]
    id: HashValue,
    /// The container for the actual block
    block_data: BlockData,
    /// Signature that the hash of this block has been authored by the owner of
    /// the private key, this is only set within Proposal blocks
    signature: Option<ConsensusSignature>,
    /// Optional VRF proof tp prove the author is a valid proposer in this
    /// round.
    vrf_nonce_and_proof: Option<(u64, ConsensusVRFProof)>,
}

#[derive(Deserialize)]
pub struct BlockUnchecked {
    block_data: BlockDataUnchecked,
    signature: Option<ConsensusSignature>,
    vrf_nonce_and_proof: Option<(u64, ConsensusVRFProof)>,
}

impl From<BlockUnchecked> for Block {
    fn from(b: BlockUnchecked) -> Self {
        let block_data: BlockData = b.block_data.into();
        Self {
            id: block_data.hash(),
            block_data,
            signature: b.signature,
            vrf_nonce_and_proof: b.vrf_nonce_and_proof,
        }
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result { write!(f, "{}", self) }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let nil_marker = if self.is_nil_block() { " (NIL)" } else { "" };
        write!(
            f,
            "[id: {}{}, epoch: {}, round: {:02}, parent_id: {}]",
            self.id,
            nil_marker,
            self.epoch(),
            self.round(),
            self.quorum_cert().certified_block().id(),
        )
    }
}

impl Block {
    pub fn author(&self) -> Option<Author> { self.block_data.author() }

    pub fn epoch(&self) -> u64 { self.block_data.epoch() }

    pub fn id(&self) -> HashValue { self.id }

    // Is this block a parent of the parameter block?
    #[cfg(test)]
    pub fn is_parent_of(&self, block: &Self) -> bool {
        block.parent_id() == self.id
    }

    pub fn parent_id(&self) -> HashValue {
        self.block_data.quorum_cert().certified_block().id()
    }

    pub fn payload(&self) -> Option<&Payload> { self.block_data.payload() }

    pub fn quorum_cert(&self) -> &QuorumCert { self.block_data.quorum_cert() }

    pub fn round(&self) -> Round { self.block_data.round() }

    pub fn signature(&self) -> Option<&ConsensusSignature> {
        self.signature.as_ref()
    }

    pub fn vrf_proof(&self) -> Option<&ConsensusVRFProof> {
        self.vrf_nonce_and_proof
            .as_ref()
            .map(|(_nonce, proof)| proof)
    }

    pub fn vrf_nonce(&self) -> Option<u64> {
        self.vrf_nonce_and_proof
            .as_ref()
            .map(|(nonce, _proof)| *nonce)
    }

    pub fn set_vrf_nonce_and_proof(
        &mut self, vrf_nonce_and_proof: (u64, ConsensusVRFProof),
    ) {
        debug_assert!(self.vrf_nonce_and_proof.is_none());
        self.vrf_nonce_and_proof = Some(vrf_nonce_and_proof);
    }

    pub fn timestamp_usecs(&self) -> u64 { self.block_data.timestamp_usecs() }

    pub fn gen_block_info(
        &self, executed_state_id: HashValue, version: Version,
        next_epoch_state: Option<EpochState>,
        pivot: Option<PivotBlockDecision>,
    ) -> BlockInfo {
        BlockInfo::new(
            self.epoch(),
            self.round(),
            self.id(),
            executed_state_id,
            version,
            self.timestamp_usecs(),
            next_epoch_state,
            pivot,
        )
    }

    pub fn block_data(&self) -> &BlockData { &self.block_data }

    pub fn is_genesis_block(&self) -> bool {
        self.block_data.is_genesis_block()
    }

    pub fn is_nil_block(&self) -> bool { self.block_data.is_nil_block() }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn make_genesis_block() -> Self {
        Self::make_genesis_block_from_ledger_info(&LedgerInfo::mock_genesis(
            None,
        ))
    }

    /// Construct new genesis block for next epoch deterministically from the
    /// end-epoch LedgerInfo We carry over most fields except round and
    /// block id
    pub fn make_genesis_block_from_ledger_info(
        ledger_info: &LedgerInfo,
    ) -> Self {
        let block_data = BlockData::new_genesis_from_ledger_info(ledger_info);
        Block {
            id: block_data.hash(),
            block_data,
            signature: None,
            vrf_nonce_and_proof: None,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    // This method should only used by tests and fuzzers to produce arbitrary
    // Block types.
    pub fn new_for_testing(
        id: HashValue, block_data: BlockData,
        signature: Option<ConsensusSignature>,
        vrf_proof: Option<(u64, ConsensusVRFProof)>,
    ) -> Self {
        Block {
            id,
            block_data,
            signature,
            vrf_nonce_and_proof: vrf_proof,
        }
    }

    /// The NIL blocks are special: they're not carrying any real payload and
    /// are generated independently by different validators just to fill in
    /// the round with some QC.
    pub fn new_nil(round: Round, quorum_cert: QuorumCert) -> Self {
        let block_data = BlockData::new_nil(round, quorum_cert);

        Block {
            id: block_data.hash(),
            block_data,
            signature: None,
            vrf_nonce_and_proof: None,
        }
    }

    // Test only?
    pub fn new_proposal(
        payload: Payload, round: Round, timestamp_usecs: u64,
        quorum_cert: QuorumCert, validator_signer: &ValidatorSigner,
    ) -> Self {
        let block_data = BlockData::new_proposal(
            payload,
            validator_signer.author(),
            round,
            timestamp_usecs,
            quorum_cert,
        );

        Self::new_proposal_from_block_data(block_data, validator_signer)
    }

    // Test only?
    pub fn new_proposal_from_block_data(
        block_data: BlockData, validator_signer: &ValidatorSigner,
    ) -> Self {
        let signature = validator_signer.sign(&block_data);
        Self::new_proposal_from_block_data_and_signature(
            block_data, signature, None,
        )
    }

    pub fn new_proposal_from_block_data_and_signature(
        block_data: BlockData, signature: ConsensusSignature,
        vrf_nonce_and_proof: Option<(u64, ConsensusVRFProof)>,
    ) -> Self {
        Block {
            id: block_data.hash(),
            block_data,
            signature: Some(signature),
            vrf_nonce_and_proof,
        }
    }

    /// Verifies that the proposal and the QC are correctly signed.
    /// If this is the genesis block, we skip these checks.
    pub fn validate_signature(
        &self, validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        match self.block_data.block_type() {
            BlockType::Genesis => {
                bail!("We should not accept genesis from others")
            }
            BlockType::NilBlock => self.quorum_cert().verify(validator),
            BlockType::Proposal { author, .. } => {
                let signature = self.signature.as_ref().ok_or_else(|| {
                    format_err!("Missing signature in Proposal")
                })?;
                validator.verify(*author, &self.block_data, signature)?;
                self.quorum_cert().verify(validator)
            }
        }
    }

    /// Makes sure that the proposal makes sense, independently of the current
    /// state. If this is the genesis block, we skip these checks.
    pub fn verify_well_formed(&self) -> anyhow::Result<()> {
        ensure!(
            !self.is_genesis_block(),
            "We must not accept genesis from others"
        );
        let parent = self.quorum_cert().certified_block();
        ensure!(
            parent.round() < self.round(),
            "Block must have a greater round than parent's block"
        );
        ensure!(
            parent.epoch() == self.epoch(),
            "block's parent should be in the same epoch"
        );
        if parent.has_reconfiguration() {
            ensure!(
                self.payload().map_or(true, |p| p.is_empty()),
                "Reconfiguration suffix should not carry payload"
            );
        }
        if self.is_nil_block() || parent.has_reconfiguration() {
            ensure!(
                self.timestamp_usecs() == parent.timestamp_usecs(),
                "Nil/reconfig suffix block must have same timestamp as parent"
            );
        } else {
            ensure!(
                self.timestamp_usecs() > parent.timestamp_usecs(),
                "Blocks must have strictly increasing timestamps"
            );

            let current_ts = duration_since_epoch();

            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs()
                    <= (current_ts.as_micros() as u64)
                        .saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
        }
        ensure!(
            !self.quorum_cert().ends_epoch(),
            "Block cannot be proposed in an epoch that has ended"
        );
        debug_checked_verify_eq!(
            self.id(),
            self.block_data.hash(),
            "Block id mismatch the hash"
        );
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(rename = "Block")]
        struct BlockWithoutId {
            block_data: BlockData,
            signature: Option<ConsensusSignature>,
            vrf_nonce_and_proof: Option<(u64, ConsensusVRFProof)>,
        }

        let BlockWithoutId {
            block_data,
            signature,
            vrf_nonce_and_proof,
        } = BlockWithoutId::deserialize(deserializer)?;

        Ok(Block {
            id: block_data.hash(),
            block_data,
            signature,
            vrf_nonce_and_proof,
        })
    }
}

impl From<&Block> for BlockMetadata {
    fn from(block: &Block) -> Self {
        Self::new(
            block.id(),
            block.round(),
            block.timestamp_usecs(),
            // an ordered vector of voters' account address
            block
                .quorum_cert()
                .ledger_info()
                .signatures()
                .keys()
                .cloned()
                .collect(),
            // For nil block, we use 0x0 which is convention for nil address in
            // move.
            block.author().unwrap_or(AccountAddress::ZERO),
        )
    }
}
