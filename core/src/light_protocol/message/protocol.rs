// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{message::RequestId, storage::StateProof};
use cfx_types::H256;
use primitives::StateRoot as PrimitiveStateRoot;
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct GetStateRoot {
    pub request_id: RequestId,
    pub epoch: u64,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateRoot {
    pub request_id: RequestId,
    pub pivot_hash: H256,
    pub state_root: PrimitiveStateRoot,
}

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct GetStateEntry {
    pub request_id: RequestId,
    pub epoch: u64,
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateEntry {
    pub request_id: RequestId,
    pub pivot_hash: H256,
    pub state_root: PrimitiveStateRoot,
    pub entry: Option<Vec<u8>>,
    pub proof: StateProof,
}
