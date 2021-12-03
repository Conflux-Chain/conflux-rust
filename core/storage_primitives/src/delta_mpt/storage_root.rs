#[derive(Clone, Debug, RlpEncodable, RlpDecodable, Serialize)]
pub struct NodeMerkleTriplet {
    pub delta: MptValue<H256>,
    pub intermediate: MptValue<H256>,
    pub snapshot: Option<H256>,
}

pub type StorageRoot = NodeMerkleTriplet;

use crate::MptValue;

use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::Serialize;
