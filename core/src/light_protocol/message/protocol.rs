// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::NodeType;
use crate::{message::RequestId, storage::StateProof};
use cfx_types::H256;
use primitives::{
    BlockHeader as PrimitiveBlockHeader, StateRoot as PrimitiveStateRoot,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct StatusPing {
    pub genesis_hash: H256,
    pub network_id: u8,
    pub node_type: NodeType,
    pub protocol_version: u8,
}

#[derive(Clone, Debug, PartialEq, RlpEncodable, RlpDecodable)]
pub struct StatusPong {
    pub best_epoch: u64,
    pub genesis_hash: H256,
    pub network_id: u8,
    pub node_type: NodeType,
    pub protocol_version: u8,
    pub terminals: Vec<H256>,
}

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

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct BlockHashes {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetBlockHeaders {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct BlockHeaders {
    pub request_id: RequestId,
    pub headers: Vec<PrimitiveBlockHeader>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct NewBlockHashes {
    pub hashes: Vec<H256>,
}
