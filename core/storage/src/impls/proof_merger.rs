// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// `TrieProofMerger` and `StateProofMerger` allow us to combine multiple proofs
// into a single proof. Any key that can be verified by any of the original
// proofs can also be verified by the combined proof. While a single proof is
// usually a path in the MPT from the root to a node, the combined proof is a
// subtree rooted at the MPT's root.

#[derive(Debug, Default)]
struct TrieProofMerger {
    hashes: HashSet<MerkleHash>,
    nodes: Vec<TrieProofNode>,
}

impl TrieProofMerger {
    pub fn merge(&mut self, proof: TrieProof) {
        for node in proof.into_proof_nodes() {
            if !self.hashes.contains(&node.get_merkle()) {
                self.hashes.insert(*node.get_merkle());
                self.nodes.push(node);
            }
        }
    }

    pub fn finish(self) -> Result<TrieProof> {
        TrieProof::new(self.nodes)
    }
}

#[derive(Debug, Default)]
pub struct StateProofMerger {
    delta: Option<TrieProofMerger>,
    intermediate: Option<TrieProofMerger>,
    snapshot: Option<TrieProofMerger>,
}

impl StateProofMerger {
    pub fn merge(&mut self, proof: StateProof) {
        let StateProof {
            delta_proof,
            intermediate_proof,
            snapshot_proof,
        } = proof;

        if let Some(proof) = delta_proof {
            match self.delta {
                Some(ref mut merger) => merger.merge(proof),
                None => {
                    let mut merger = TrieProofMerger::default();
                    merger.merge(proof);
                    self.delta = Some(merger);
                }
            }
        }

        if let Some(proof) = intermediate_proof {
            match self.intermediate {
                Some(ref mut merger) => merger.merge(proof),
                None => {
                    let mut merger = TrieProofMerger::default();
                    merger.merge(proof);
                    self.intermediate = Some(merger);
                }
            }
        }

        if let Some(proof) = snapshot_proof {
            match self.snapshot {
                Some(ref mut merger) => merger.merge(proof),
                None => {
                    let mut merger = TrieProofMerger::default();
                    merger.merge(proof);
                    self.snapshot = Some(merger);
                }
            }
        }
    }

    pub fn finish(self) -> Result<StateProof> {
        let mut proof = StateProof::default();

        if let Some(merger) = self.delta {
            proof.with_delta(Some(merger.finish()?));
        }

        if let Some(merger) = self.intermediate {
            proof.with_intermediate(Some(merger.finish()?));
        }

        if let Some(merger) = self.snapshot {
            proof.with_snapshot(Some(merger.finish()?));
        }

        Ok(proof)
    }
}

use crate::impls::{
    errors::*,
    merkle_patricia_trie::{trie_proof::TrieProofNode, TrieProof},
    state_proof::StateProof,
};
use primitives::MerkleHash;
use std::collections::HashSet;
