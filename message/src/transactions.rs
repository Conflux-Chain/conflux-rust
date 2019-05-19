// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Message, MsgId, RequestId};
use primitives::{transaction::TxPropagateId, TransactionWithSignature};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    collections::HashSet,
    mem,
    ops::{Deref, DerefMut},
};

#[derive(Debug, PartialEq)]
pub struct Transactions {
    pub transactions: Vec<TransactionWithSignature>,
}

impl Message for Transactions {
    fn msg_id(&self) -> MsgId { MsgId::TRANSACTIONS }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 1 }
}

impl Encodable for Transactions {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append_list(&self.transactions);
    }
}

impl Decodable for Transactions {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Transactions {
            transactions: rlp.as_list()?,
        })
    }
}

////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct TransactionPropagationControl {
    pub catch_up_mode: bool,
}

impl Message for TransactionPropagationControl {
    fn msg_id(&self) -> MsgId { MsgId::TRANSACTION_PROPAGATION_CONTROL }
}

impl Encodable for TransactionPropagationControl {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append(&self.catch_up_mode);
    }
}

impl Decodable for TransactionPropagationControl {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(TransactionPropagationControl {
            catch_up_mode: rlp.as_val()?,
        })
    }
}

/////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct TransIndex(usize, usize);

impl TransIndex {
    pub fn new(index: (usize, usize)) -> Self { TransIndex(index.0, index.1) }

    pub fn first(&self) -> usize { self.0 }

    pub fn second(&self) -> usize { self.1 }
}

impl Encodable for TransIndex {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(2).append(&self.0).append(&self.1);
    }
}

impl Decodable for TransIndex {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(TransIndex(rlp.val_at(0)?, rlp.val_at(1)?))
    }
}

#[derive(Debug, PartialEq)]
pub struct TransactionDigest {
    pub short_id: TxPropagateId,
    pub source_index: TransIndex,
}

impl TransactionDigest {
    pub fn size() -> usize { mem::size_of::<Self>() }
}

impl Encodable for TransactionDigest {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.short_id)
            .append(&self.source_index);
    }
}

impl Decodable for TransactionDigest {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(TransactionDigest {
            short_id: rlp.val_at(0)?,
            source_index: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct TransactionDigests {
    pub trans_digests: Vec<TransactionDigest>,
}

impl Message for TransactionDigests {
    fn msg_id(&self) -> MsgId { MsgId::TRANSACTION_DIGESTS }

    fn is_size_sensitive(&self) -> bool { self.trans_digests.len() > 1 }
}

impl Encodable for TransactionDigests {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append_list(&self.trans_digests);
    }
}

impl Decodable for TransactionDigests {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(TransactionDigests {
            trans_digests: rlp.as_list()?,
        })
    }
}

/////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct GetTransactions {
    pub request_id: RequestId,
    pub indices: Vec<TransIndex>,
    pub tx_ids: HashSet<TxPropagateId>,
}

impl Message for GetTransactions {
    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS }
}

impl Deref for GetTransactions {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetTransactions {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetTransactions {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.indices);
    }
}

impl Decodable for GetTransactions {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetTransactions {
            request_id: rlp.val_at(0)?,
            indices: rlp.list_at(1)?,
            tx_ids: HashSet::new(),
        })
    }
}

///////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct GetTransactionsResponse {
    pub request_id: RequestId,
    pub transactions: Vec<TransactionWithSignature>,
}

impl Message for GetTransactionsResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }
}

impl Deref for GetTransactionsResponse {
    type Target = RequestId;

    fn deref(&self) -> &Self::Target { &self.request_id }
}

impl DerefMut for GetTransactionsResponse {
    fn deref_mut(&mut self) -> &mut RequestId { &mut self.request_id }
}

impl Encodable for GetTransactionsResponse {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.request_id)
            .append_list(&self.transactions);
    }
}

impl Decodable for GetTransactionsResponse {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(GetTransactionsResponse {
            request_id: rlp.val_at(0)?,
            transactions: rlp.list_at(1)?,
        })
    }
}
