// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    sync::{
        message::{
            metrics::TX_HANDLE_TIMER, Context, DynamicCapability, Handleable,
            Key, KeyContainer, msgid,
        },
        request_manager::Request,
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use metrics::MeterTimer;
use primitives::{transaction::TxPropagateId, TransactionWithSignature};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{
    RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper,
};
use std::{collections::HashSet, time::Duration};
use siphasher::sip::SipHasher24;
use std::{any::Any, collections::HashSet, hash::Hasher, time::Duration};

#[derive(Debug, PartialEq, RlpDecodableWrapper, RlpEncodableWrapper)]
pub struct Transactions {
    pub transactions: Vec<TransactionWithSignature>,
}

impl Handleable for Transactions {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions = self.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            ctx.peer
        );

        let peer_info = ctx.manager.syn.get_peer_info(&ctx.peer)?;
        let should_disconnect = {
            let mut peer_info = peer_info.write();
            if peer_info
                .notified_capabilities
                .contains(DynamicCapability::TxRelay(false))
            {
                peer_info.received_transaction_count += transactions.len();
                peer_info.received_transaction_count
                    > ctx
                        .manager
                        .protocol_config
                        .max_trans_count_received_in_catch_up
                        as usize
            } else {
                false
            }
        };

        if should_disconnect {
            bail!(ErrorKind::TooManyTrans);
        }

        let (signed_trans, _) = ctx
            .manager
            .graph
            .consensus
            .txpool
            .insert_new_transactions(transactions);

        ctx.manager
            .request_manager
            .append_received_transactions(signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }
}

/////////////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq)]
pub struct TransactionDigests {
    pub window_index: usize,
    pub key1: u64,
    pub key2: u64,
    trans_short_ids: Vec<u8>,
    pub trans_long_ids: Vec<H256>,
}

impl Handleable for TransactionDigests {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        {
            let peer_info = ctx.manager.syn.get_peer_info(&ctx.peer)?;

            let mut peer_info = peer_info.write();
            if peer_info
                .notified_capabilities
                .contains(DynamicCapability::TxRelay(false))
            {
                peer_info.received_transaction_count +=
                    self.trans_short_ids.len() + self.trans_long_ids.len();
                if peer_info.received_transaction_count
                    > ctx
                        .manager
                        .protocol_config
                        .max_trans_count_received_in_catch_up
                        as usize
                {
                    bail!(ErrorKind::TooManyTrans);
                }
                if self.trans_short_ids.len() % Self::SHORT_ID_SIZE_IN_BYTES
                    != 0
                {
                    bail!(ErrorKind::InvalidMessageFormat);
                }
            }
        }

        ctx.manager
            .request_manager
            .request_transactions_from_digest(ctx.io, ctx.peer, &self);

        Ok(())
    }
}

impl Encodable for TransactionDigests {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(5)
            .append(&self.window_index)
            .append(&self.key1)
            .append(&self.key2)
            .append_list(&self.trans_short_ids)
            .append_list(&self.trans_long_ids);
    }
}

impl Decodable for TransactionDigests {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 5 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let trans_short_ids = rlp.list_at(3)?;
        let trans_long_ids = rlp.list_at(4)?;
        if trans_short_ids.len() % TransactionDigests::SHORT_ID_SIZE_IN_BYTES
            != 0
        {
            return Err(DecoderError::Custom(
                "TransactionDigests length Error!",
            ));
        }
        Ok(TransactionDigests {
            window_index: rlp.val_at(0)?,
            key1: rlp.val_at(1)?,
            key2: rlp.val_at(2)?,
            trans_short_ids,
            trans_long_ids,
        })
    }
}

impl TransactionDigests {
    const SHORT_ID_SIZE_IN_BYTES: usize = 4;

    pub fn new(
        window_index: usize, key1: u64, key2: u64, trans_short_ids: Vec<u8>,
        trans_long_ids: Vec<H256>,
    ) -> TransactionDigests
    {
        TransactionDigests {
            window_index,
            key1,
            key2,
            trans_short_ids,
            trans_long_ids,
        }
    }

    pub fn get_decomposed_short_ids(&self) -> (Vec<u8>, Vec<TxPropagateId>) {
        let mut random_byte_vector: Vec<u8> = Vec::new();
        let mut fixed_bytes_vector: Vec<TxPropagateId> = Vec::new();

        for i in (0..self.trans_short_ids.len())
            .step_by(TransactionDigests::SHORT_ID_SIZE_IN_BYTES)
        {
            random_byte_vector.push(self.trans_short_ids[i]);
            fixed_bytes_vector.push(TransactionDigests::to_u24(
                self.trans_short_ids[i + 1],
                self.trans_short_ids[i + 2],
                self.trans_short_ids[i + 3],
            ));
        }

        (random_byte_vector, fixed_bytes_vector)
    }

    pub fn len(&self) -> usize {
        self.trans_short_ids.len() / TransactionDigests::SHORT_ID_SIZE_IN_BYTES
    }

    pub fn to_u24(v1: u8, v2: u8, v3: u8) -> u32 {
        ((v1 as u32) << 16) + ((v2 as u32) << 8) + v3 as u32
    }

    pub fn append_short_trans_id(
        message: &mut Vec<u8>, key1: u64, key2: u64, transaction_id: &H256,
    ) {
        message.push(TransactionDigests::get_random_byte(
            transaction_id,
            key1,
            key2,
        ));
        message.push(transaction_id[29]);
        message.push(transaction_id[30]);
        message.push(transaction_id[31]);
    }

    pub fn append_long_trans_id(message: &mut Vec<H256>, transaction_id: H256) {
        message.push(transaction_id);
    }

    pub fn get_random_byte(transaction_id: &H256, key1: u64, key2: u64) -> u8 {
        let mut hasher = SipHasher24::new_with_keys(key1, key2);
        hasher.write(transaction_id.as_ref());
        (hasher.finish() & 0xff) as u8
    }
}

/////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct GetTransactions {
    pub request_id: RequestId,
    pub window_index: usize,
    pub indices: Vec<usize>,
    pub long_id_indices: Vec<usize>,
    pub short_tx_ids: HashSet<TxPropagateId>,
    pub long_tx_ids: HashSet<H256>,
}

impl Request for GetTransactions {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.transaction_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut short_inflight_keys =
           inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut long_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS_FROM_LONG_ID);
        for tx in &self.short_tx_ids {
            short_inflight_keys.remove(&Key::Id(*tx));
        }
        for tx in &self.long_tx_ids{
            long_inflight_keys.remove(&Key::Hash(*tx));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut short_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut long_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS_FROM_LONG_ID);
        let mut short_tx_ids: HashSet<TxPropagateId> = HashSet::new();
        let mut long_tx_ids: HashSet<H256> = HashSet::new();
        for id in self.short_tx_ids.iter() {
            if short_inflight_keys.insert(Key::Id(*id)) {
                short_tx_ids.insert(*id);
            }
        }
        for id in self.long_tx_ids.iter(){
            if long_inflight_keys.insert(Key::Hash(*id)){
                long_tx_ids.insert(*id);
            }
        }

        self.short_tx_ids = short_tx_ids;
        self.long_tx_ids = long_tx_ids;
    }

    fn is_empty(&self) -> bool { self.long_id_indices.is_empty() && self.indices.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> { None }
}

impl Handleable for GetTransactions {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions =
            ctx.manager.request_manager.get_sent_transactions(
                self.window_index,
                &self.indices,
            );
        let long_indices_transactions = ctx
            .manager
            .request_manager
            .get_sent_transactions(self.window_index, &self.long_id_indices);
        let long_trans_ids = long_indices_transactions
            .into_iter()
            .map(|tx| tx.hash())
            .collect();
        let response = GetTransactionsResponse {
            request_id: self.request_id,
            transactions: transactions,
            long_trans_ids,
        };
        debug!(
            "on_get_transactions request {} txs, {} long ids, returned {} txs {} long ids",
            self.indices.len(),
            self.long_id_indices.len(),
            response.transactions.len(),
            response.long_trans_ids.len(),
        );

        ctx.send_response(&response)
    }
}

impl Encodable for GetTransactions {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(4)
            .append(&self.request_id)
            .append(&self.window_index)
            .append_list(&self.indices)
            .append_list(&self.long_id_indices);
    }
}

impl Decodable for GetTransactions {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetTransactions {
            request_id: rlp.val_at(0)?,
            window_index: rlp.val_at(1)?,
            indices: rlp.list_at(2)?,
            long_id_indices: rlp.list_at(3)?,
            short_tx_ids: HashSet::new(),
            long_tx_ids: HashSet::new(),
        })
    }
}

/////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct GetTransactionsFromLongId {
    pub request_id: RequestId,
    pub window_index: usize,
    pub indices: Vec<usize>,
    pub tx_ids: HashSet<H256>,
}

impl Request for GetTransactionsFromLongId {
    fn as_message(&self) -> &dyn Message { self }

    fn as_any(&self) -> &dyn Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.transaction_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        for tx_id in self.tx_ids.iter() {
            inflight_keys.remove(&Key::Hash(*tx_id));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());

        let mut tx_ids: HashSet<H256> = HashSet::new();
        for id in self.tx_ids.iter() {
            if inflight_keys.insert(Key::Hash(*id)) {
                tx_ids.insert(*id);
            }
        }

        self.tx_ids = tx_ids;
    }

    fn is_empty(&self) -> bool { self.tx_ids.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> { None }
}

impl Handleable for GetTransactionsFromLongId {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions =
            ctx.manager.request_manager.get_sent_transactions(
                self.window_index,
                &self.indices,
            );

        let response = GetTransactionsFromLongIdResponse {
            request_id: self.request_id,
            transactions: transactions
        };
        debug!(
            "on_get_transactions_from_long_id request {} txs, returned {} txs",
            self.indices.len(),
            response.transactions.len(),
        );

        ctx.send_response(&response)
    }
}

impl Encodable for GetTransactionsFromLongId {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.window_index)
            .append_list(&self.indices);
    }
}

impl Decodable for GetTransactionsFromLongId {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetTransactionsFromLongId {
            request_id: rlp.val_at(0)?,
            window_index: rlp.val_at(1)?,
            indices: rlp.list_at(2)?,
            tx_ids: HashSet::new(),
        })
    }
}


///////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct GetTransactionsResponse {
    pub request_id: RequestId,
    pub transactions: Vec<TransactionWithSignature>,
    pub long_trans_ids: Vec<H256>,
}

impl Handleable for GetTransactionsResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(TX_HANDLE_TIMER.as_ref());

        debug!("on_get_transactions_response {:?}", self.request_id);

        let req = ctx.match_request(self.request_id)?;
        let req = req.downcast_ref::<GetTransactions>(
            ctx.io,
            &ctx.manager.request_manager,
            false,
        )?;

        // FIXME: Do some check based on transaction request.

        debug!(
            "Received {:?} transactions from Peer {:?}",
            self.transactions.len(),
            ctx.peer
        );

        let (signed_trans, _) = ctx
            .manager
            .graph
            .consensus
            .txpool
            .insert_new_transactions(self.transactions);

        ctx.manager
            .request_manager
            .transactions_received_from_digests(ctx.io, &req, signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        if req.long_id_indices.len() >0 && self.long_trans_ids.is_empty(){
            ctx.manager
                .request_manager
                .request_transactions_from_long_tx_ids(ctx.io, ctx.peer, self.long_trans_ids, req.window_index, &req.long_id_indices);
        }
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct GetTransactionsFromLongIdResponse {
    pub request_id: RequestId,
    pub transactions: Vec<TransactionWithSignature>,
}

impl Handleable for GetTransactionsFromLongIdResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(TX_HANDLE_TIMER.as_ref());

        debug!("on_get_transactions_from_long_id_response {:?}", self.request_id);

        let req = ctx.match_request(self.request_id)?;
        let req = req.downcast_ref::<GetTransactionsFromLongId>(
            ctx.io,
            &ctx.manager.request_manager,
            false,
        )?;

        // FIXME: Do some check based on transaction request.

        debug!(
            "Received {:?} transactions from Peer {:?}",
            self.transactions.len(),
            ctx.peer
        );

        let (signed_trans, _) = ctx
            .manager
            .graph
            .consensus
            .txpool
            .insert_new_transactions(self.transactions);

        ctx.manager
            .request_manager
            .transactions_received_from_long_id(&req, signed_trans);

        debug!("Transactions successfully inserted to transaction pool");
        Ok(())
    }
}
