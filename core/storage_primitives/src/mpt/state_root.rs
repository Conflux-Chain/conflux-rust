use cfx_primitives::MerkleHash;
use cfx_types::H256;

use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::{Deserialize, Serialize};

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpDecodable,
    RlpEncodable,
)]
pub struct StateRoot(pub H256);

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 { self.0.clone() }

    pub fn genesis(genesis_root: &MerkleHash) -> StateRoot {
        warn!(
            "Make genesis root with dropped parameter {:?}",
            genesis_root
        );
        StateRoot(genesis_root.clone())
    }
}
