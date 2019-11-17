// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Bloom, H256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

use super::NodeType;
use crate::{message::RequestId, storage::StateProof};

use primitives::{
    BlockHeader as PrimitiveBlockHeader, Receipt as PrimitiveReceipt,
    SignedTransaction, StateRoot as PrimitiveStateRoot,
};

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StatusPing {
    pub genesis_hash: H256,
    pub node_type: NodeType,
    pub protocol_version: u8,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StatusPong {
    pub best_epoch: u64,
    pub genesis_hash: H256,
    pub node_type: NodeType,
    pub protocol_version: u8,
    pub terminals: Vec<H256>,
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

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetReceipts {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct ReceiptsWithEpoch {
    pub epoch: u64,
    pub receipts: Vec<Vec<PrimitiveReceipt>>,
}

impl Encodable for ReceiptsWithEpoch {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2);
        stream.append(&self.epoch);

        stream.begin_list(self.receipts.len());
        for r in &self.receipts {
            stream.append_list(r);
        }
    }
}

impl Decodable for ReceiptsWithEpoch {
    fn decode(rlp: &Rlp) -> Result<ReceiptsWithEpoch, DecoderError> {
        let epoch = rlp.val_at(0)?;

        let receipts = rlp
            .at(1)?
            .into_iter()
            .map(|x| Ok(x.as_list()?))
            .collect::<Result<_, _>>()?;

        Ok(ReceiptsWithEpoch { epoch, receipts })
    }
}

#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct Receipts {
    pub request_id: RequestId,
    pub receipts: Vec<ReceiptsWithEpoch>,
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

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetWitnessInfo {
    pub request_id: RequestId,
    pub witnesses: Vec<u64>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct WitnessInfoWithHeight {
    pub height: u64,
    pub state_roots: Vec<H256>,
    pub receipt_hashes: Vec<H256>,
    pub bloom_hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct WitnessInfo {
    pub request_id: RequestId,
    pub infos: Vec<WitnessInfoWithHeight>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetBlooms {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct BloomWithEpoch {
    pub epoch: u64,
    pub bloom: Bloom,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct Blooms {
    pub request_id: RequestId,
    pub blooms: Vec<BloomWithEpoch>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetBlockTxs {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct BlockTxsWithHash {
    pub hash: H256,
    pub block_txs: Vec<SignedTransaction>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct BlockTxs {
    pub request_id: RequestId,
    pub block_txs: Vec<BlockTxsWithHash>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetStateRoots {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateRootWithEpoch {
    pub epoch: u64,
    pub state_root: PrimitiveStateRoot,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateRoots {
    pub request_id: RequestId,
    pub state_roots: Vec<StateRootWithEpoch>,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable,
)]
pub struct StateKey {
    pub epoch: u64,
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetStateEntries {
    pub request_id: RequestId,
    pub keys: Vec<StateKey>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateEntryWithKey {
    pub key: StateKey,
    pub entry: Option<Vec<u8>>,
    pub proof: StateProof,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct StateEntries {
    pub request_id: RequestId,
    pub entries: Vec<StateEntryWithKey>,
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct GetTxInfos {
    pub request_id: RequestId,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, Default)]
pub struct TxInfo {
    pub epoch: u64,
    pub block_hash: H256,
    pub index: usize,
    pub epoch_receipts: Vec<Vec<PrimitiveReceipt>>,
    pub block_txs: Vec<SignedTransaction>,
    pub tx_hash: H256,
}

impl Encodable for TxInfo {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(6);
        stream.append(&self.epoch);
        stream.append(&self.block_hash);
        stream.append(&self.index);

        stream.begin_list(self.epoch_receipts.len());
        for r in &self.epoch_receipts {
            stream.append_list(r);
        }

        stream.append_list(&self.block_txs);
        stream.append(&self.tx_hash);
    }
}

impl Decodable for TxInfo {
    fn decode(rlp: &Rlp) -> Result<TxInfo, DecoderError> {
        let epoch = rlp.val_at(0)?;
        let block_hash = rlp.val_at(1)?;
        let index = rlp.val_at(2)?;

        let epoch_receipts = rlp
            .at(3)?
            .into_iter()
            .map(|x| Ok(x.as_list()?))
            .collect::<Result<_, _>>()?;

        let block_txs = rlp.list_at(4)?;
        let tx_hash = rlp.val_at(5)?;

        Ok(TxInfo {
            epoch,
            block_hash,
            index,
            epoch_receipts,
            block_txs,
            tx_hash,
        })
    }
}

#[derive(Clone, Debug, Default, RlpEncodable, RlpDecodable)]
pub struct TxInfos {
    pub request_id: RequestId,
    pub infos: Vec<TxInfo>,
}
