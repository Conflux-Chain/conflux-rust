// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        GetBlockTxnResponse, Message, MsgId, Request, RequestContext, RequestId,
    },
    Error, ErrorKind,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Default)]
pub struct GetBlockTxn {
    pub request_id: RequestId,
    pub block_hash: H256,
    pub indexes: Vec<usize>,
}

impl Request for GetBlockTxn {
    fn handle(&self, context: &RequestContext) -> Result<(), Error> {
        match context.graph.block_by_hash(&self.block_hash) {
            Some(block) => {
                debug!("Process get_blocktxn hash={:?}", block.hash());
                let mut tx_resp = Vec::with_capacity(self.indexes.len());
                let mut last = 0;
                for index in self.indexes.iter() {
                    last += *index;
                    if last >= block.transactions.len() {
                        warn!(
                            "Request tx index out of bound, peer={}, hash={}",
                            context.peer,
                            block.hash()
                        );
                        return Err(ErrorKind::Invalid.into());
                    }
                    tx_resp.push(block.transactions[last].transaction.clone());
                    last += 1;
                }
                let response = GetBlockTxnResponse {
                    request_id: self.request_id.clone(),
                    block_hash: self.block_hash.clone(),
                    block_txn: tx_resp,
                };

                context.send_response(&response)
            }
            None => {
                warn!(
                    "Get blocktxn request of non-existent block, hash={}",
                    self.block_hash
                );

                let response = GetBlockTxnResponse {
                    request_id: self.request_id.clone(),
                    block_hash: H256::default(),
                    block_txn: Vec::new(),
                };

                context.send_response(&response)
            }
        }
    }
}

impl Message for GetBlockTxn {
    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_TXN }
}

impl Deref for GetBlockTxn {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetBlockTxn {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetBlockTxn {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.block_hash)
            .append_list(&self.indexes);
    }
}

impl Decodable for GetBlockTxn {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetBlockTxn {
            request_id: rlp.val_at(0)?,
            block_hash: rlp.val_at(1)?,
            indexes: rlp.list_at(2)?,
        })
    }
}
