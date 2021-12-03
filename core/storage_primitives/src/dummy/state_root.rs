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
    RlpEncodable,
    RlpDecodable,
)]
#[serde(rename_all = "camelCase")]
pub struct StateRoot;

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 { todo!() }

    pub fn genesis(genesis_root: &MerkleHash) -> StateRoot { todo!() }
}
