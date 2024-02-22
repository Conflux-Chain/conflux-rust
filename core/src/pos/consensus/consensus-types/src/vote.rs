// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{common::Author, timeout::Timeout, vote_data::VoteData};
use anyhow::{ensure, Context};
use diem_crypto::hash::CryptoHash;
use diem_types::{
    ledger_info::LedgerInfo, validator_config::ConsensusSignature,
    validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier,
};
use serde::{Deserialize, Serialize};
use short_hex_str::AsShortHexStr;
use std::fmt::{Debug, Display, Formatter};

/// Vote is the struct that is ultimately sent by the voter in response for
/// receiving a proposal.
/// Vote carries the `LedgerInfo` of a block that is going to be committed in
/// case this vote is gathers QuorumCertificate (see the detailed explanation in
/// the comments of `LedgerInfo`).
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Vote {
    /// The data of the vote
    vote_data: VoteData,
    /// The identity of the voter.
    author: Author,
    /// LedgerInfo of a block that is going to be committed in case this vote
    /// gathers QC.
    ledger_info: LedgerInfo,
    /// Signature of the LedgerInfo
    signature: ConsensusSignature,
    /// The round signatures can be aggregated into a timeout certificate if
    /// present.
    timeout_signature: Option<ConsensusSignature>,
}

// this is required by structured log
impl Debug for Vote {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for Vote {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Vote: [vote data: {}, author: {}, is_timeout: {}, {}]",
            self.vote_data,
            self.author.short_str(),
            self.is_timeout(),
            self.ledger_info
        )
    }
}

impl Vote {
    /// Generates a new Vote corresponding to the "fast-vote" path without the
    /// round signatures that can be aggregated into a timeout certificate
    pub fn new(
        vote_data: VoteData, author: Author,
        mut ledger_info_placeholder: LedgerInfo,
        validator_signer: &ValidatorSigner,
    ) -> Self {
        ledger_info_placeholder.set_consensus_data_hash(vote_data.hash());
        let signature = validator_signer.sign(&ledger_info_placeholder);
        Self::new_with_signature(
            vote_data,
            author,
            ledger_info_placeholder,
            signature,
        )
    }

    /// Generates a new Vote using a signature over the specified ledger_info
    pub fn new_with_signature(
        vote_data: VoteData, author: Author, ledger_info: LedgerInfo,
        signature: ConsensusSignature,
    ) -> Self {
        Self {
            vote_data,
            author,
            ledger_info,
            signature,
            timeout_signature: None,
        }
    }

    /// Generates a round signature, which can then be used for aggregating a
    /// timeout certificate. Typically called for generating vote messages
    /// that are sent upon timeouts.
    pub fn add_timeout_signature(&mut self, signature: ConsensusSignature) {
        if self.timeout_signature.is_some() {
            return; // round signature is already set
        }

        self.timeout_signature.replace(signature);
    }

    pub fn vote_data(&self) -> &VoteData { &self.vote_data }

    /// Return the author of the vote
    pub fn author(&self) -> Author { self.author }

    /// Return the LedgerInfo associated with this vote
    pub fn ledger_info(&self) -> &LedgerInfo { &self.ledger_info }

    /// Return the signature of the vote
    pub fn signature(&self) -> &ConsensusSignature { &self.signature }

    /// Returns the hash of the data represent by a timeout proposal
    pub fn timeout(&self) -> Timeout {
        Timeout::new(
            self.vote_data().proposed().epoch(),
            self.vote_data().proposed().round(),
        )
    }

    /// Return the epoch of the vote
    pub fn epoch(&self) -> u64 { self.vote_data.proposed().epoch() }

    /// Returns the signature for the vote_data().proposed().round() that can be
    /// aggregated for TimeoutCertificate.
    pub fn timeout_signature(&self) -> Option<&ConsensusSignature> {
        self.timeout_signature.as_ref()
    }

    /// The vote message is considered a timeout vote message if it carries a
    /// signature on the round, which can then be used for aggregating it to
    /// the TimeoutCertificate.
    pub fn is_timeout(&self) -> bool { self.timeout_signature.is_some() }

    /// Verifies that the consensus data hash of LedgerInfo corresponds to the
    /// vote info, and then verifies the signature.
    pub fn verify(&self, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            self.ledger_info.consensus_data_hash() == self.vote_data.hash(),
            "Vote's hash mismatch with LedgerInfo"
        );
        validator
            .verify(self.author(), &self.ledger_info, &self.signature)
            .context("Failed to verify Vote")?;
        if let Some(timeout_signature) = &self.timeout_signature {
            validator
                .verify(self.author(), &self.timeout(), timeout_signature)
                .context("Failed to verify Timeout Vote")?;
        }
        // Let us verify the vote data as well
        self.vote_data().verify()?;
        Ok(())
    }
}

#[test]
fn test() {
    use rustc_hex::FromHex;
    let data1= "01000000000000000200000000000000202bc30b4ba1d2f7a62c8d4141d0477cd33b6f46f2c566a815096455bb87b8f85b20000000000000000000000000000000000000000000000000000000000000000003000000000000004a39e438c5cf0500000110ae050000000000423078613064656239346661613932326665316663373362386466303061353236323530343266353262643562306234376339373230616133626334636366663462330100000000000000010000000000000020fc41c6da6b188a28803dd8e082f44494fbdc2af9a57dcdad206ad5e18449f20e20000000000000000000000000000000000000000000000000000000000000000002000000000000004a39e438c5cf0500000110ae05000000000042307861306465623934666161393232666531666337336238646630306135323632353034326635326264356230623437633937323061613362633463636666346233046ca462890f25ed9394ca9f92c979ff48e1738a81822ecab96d83813c1a433c0100000000000000000000000000000020c9533883c69d23423b7e0cf8839ab576190e7afe421283e1d7490301f749acbf200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000042307835326466636539376464656435326536633665386634356638346462303366666139373533393265626333376436376466333332643430373238383166366665208c0d17c8d9bafab28641bf731b84db92ae4222c299d5df4bfb72fdbe86b35555c001032e102a54068dd95f1d5c2c578b273dd35169f6f37490f4f732d503edc5957fafdb40e232456110f10bff94fc8700b316c47d9aa54c2c090572b837844187d87689542fa21133a873e78a3ade6ce0c1bb4897d026c889224827e00bb77572680ce7d8fde8f72b8c1993565dbff0ed8df8e65b8b7cd60aaf57f37ab1bbc3bee449d7a1e26d655c10500bc75003aea86d19a64b66ab42a0b8dcdadbc49cfea17eea1ba44f47460f0bd487a19c1cbd034576aa3ffc757628aa9541db8771ef56f201c0010f034cf25b711bea069675e0031f8018a7ed63ae32748f90fda15676df08d38d72309ced2ff3ce6cd4d2aaa3491a825808879672691d3a8109fd328ef8db8a590c02ef9172dab53b4b8f3a5214acf566d4382ec3f07ec3ef6ec7966a14f0297f0230442b11c21e90bc6bf067cc08e26cc395f12894fb829d98b9b933af834a21779e6cb484bb370243be298d366e0d9e177600b2c6d7a0bddfefd468c3f3f22c0e74c6d0c5d0908460d7914f25b306445953cc26154b4a5c74df2f672d8be574";
    let data2= "01000000000000000200000000000000202cc47aaf1d7b8ce520d59572cc2070e766048c9ecf90325df89f5816069a9f3b2000000000000000000000000000000000000000000000000000000000000000002b0000000000000022658238b8cf0500000124f504000000000042307863643562313232373066616535316165376533636635666136326564356335666261303263633761653561633230656261376132623738346139326537663334010000000000000001000000000000002003e356be377d4673b9e985551c1ec7f7806c58ff8e0550bc954367cbdd3824d12000000000000000000000000000000000000000000000000000000000000000000200000000000000a648ee34b8cf0500000124f504000000000042307863643562313232373066616535316165376533636635666136326564356335666261303263633761653561633230656261376132623738346139326537663334046ca462890f25ed9394ca9f92c979ff48e1738a81822ecab96d83813c1a433c0100000000000000000000000000000020c9533883c69d23423b7e0cf8839ab576190e7afe421283e1d7490301f749acbf20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000004230783532646663653937646465643532653663366538663435663834646230336666613937353339326562633337643637646633333264343037323838316636666520dfeb4989d67645535415b51aa5f4f64e49b5fb0223092df4fc73d1586d77aaaac0010cab4dc39f875cba05396f532e0ebbf2ea793ac672163952b4b5299cf0f3af8e9e983a338b11d39e0404dfcd2274d61a106806c28ed48fcec1e9447b6d84f004eb12b858b76e62b6b6543c91ba121dffd6eebd019dce130821d397fb3b862cdb0d2d852d4d14b6978dd8f2fd1bbc8aca5c6789dbac9c96aabf3b73c005bfbe623a54eaee9d3c452fa81586941388347212c16cf932b99ceb249ecbda94a75198fb1149b580f7ec6446c81d783345414e9e3aacdf559ee3c291849e37f367f1a100";
    let vote1: Vote =
        bcs::from_bytes(&data1.from_hex::<Vec<u8>>().unwrap()).unwrap();
    let vote2: Vote =
        bcs::from_bytes(&data2.from_hex::<Vec<u8>>().unwrap()).unwrap();
    assert_ne!(vote1, vote2)
}
