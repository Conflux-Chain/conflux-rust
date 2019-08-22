// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

use super::NodeType;
use crate::{message::RequestId, storage::StateProof};

use primitives::{
    BlockHeader as PrimitiveBlockHeader, Receipt as PrimitiveReceipt,
    SignedTransaction, StateRoot as PrimitiveStateRoot,
};

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateRootWithProof {
    pub root: PrimitiveStateRoot,
    pub proof: Vec<H256>, // witness + blamed deferred state root hashes
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StatusPing {
    pub genesis_hash: H256,
    pub network_id: u8,
    pub node_type: NodeType,
    pub protocol_version: u8,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StatusPong {
    pub best_epoch: u64,
    pub genesis_hash: H256,
    pub network_id: u8,
    pub node_type: NodeType,
    pub protocol_version: u8,
    pub terminals: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetStateRoot {
    pub request_id: RequestId,
    pub epoch: u64,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateRoot {
    pub request_id: RequestId,
    pub pivot_hash: H256,
    pub state_root: StateRootWithProof,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetStateEntry {
    pub request_id: RequestId,
    pub epoch: u64,
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateEntry {
    pub request_id: RequestId,
    pub pivot_hash: H256,
    pub state_root: StateRootWithProof,
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

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct SendRawTx {
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ReceiptsWithProof {
    pub receipts: Vec<Vec<PrimitiveReceipt>>,
    pub proof: Vec<H256>, // witness + blamed deferred receipts root hashes
}

impl Encodable for ReceiptsWithProof {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2);

        stream.begin_list(self.receipts.len());
        for r in &self.receipts {
            stream.append_list(r);
        }

        stream.append_list(&self.proof);
    }
}

impl Decodable for ReceiptsWithProof {
    fn decode(rlp: &Rlp) -> Result<ReceiptsWithProof, DecoderError> {
        let receipts = rlp
            .at(0)?
            .into_iter()
            .map(|x| Ok(x.as_list()?))
            .collect::<Result<_, _>>()?;

        let proof = rlp.list_at(1)?;

        Ok(ReceiptsWithProof { receipts, proof })
    }
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetReceipts {
    pub request_id: RequestId,
    pub epoch: u64,
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct Receipts {
    pub request_id: RequestId,
    pub pivot_hash: H256,
    pub receipts: ReceiptsWithProof,
}
#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetTxs {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct Txs {
    pub request_id: RequestId,
    pub txs: Vec<SignedTransaction>,
}
