// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        metrics::TX_HANDLE_TIMER, Context, Handleable, Key, KeyContainer,
        Message, MsgId, RequestId,
    },
    request_manager::Request,
    Error, ErrorKind, ProtocolConfiguration,
};
use metrics::MeterTimer;
use primitives::{transaction::TxPropagateId, TransactionWithSignature};
use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    any::Any,
    collections::HashSet,
    ops::{Deref, DerefMut},
    time::Duration,
};

#[derive(Debug, PartialEq)]
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
            if peer_info.notified_mode.is_some()
                && (peer_info.notified_mode.unwrap() == true)
            {
                peer_info.received_transaction_count += transactions.len();
                if peer_info.received_transaction_count
                    > ctx
                        .manager
                        .protocol_config
                        .max_trans_count_received_in_catch_up
                        as usize
                {
                    true
                } else {
                    false
                }
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
            .insert_new_transactions(&transactions);

        ctx.manager
            .request_manager
            .append_received_transactions(signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }
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

impl Handleable for TransactionPropagationControl {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_trans_prop_ctrl, peer {}, msg=:{:?}", ctx.peer, self);

        let peer_info = ctx.manager.syn.get_peer_info(&ctx.peer)?;
        peer_info.write().need_prop_trans = !self.catch_up_mode;

        Ok(())
    }
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
pub struct TransactionDigests {
    pub window_index: usize,
    pub trans_short_ids: Vec<TxPropagateId>,
}

impl Handleable for TransactionDigests {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer_info = ctx.manager.syn.get_peer_info(&ctx.peer)?;

        let mut peer_info = peer_info.write();
        if let Some(true) = peer_info.notified_mode {
            peer_info.received_transaction_count += self.trans_short_ids.len();
            if peer_info.received_transaction_count
                > ctx
                    .manager
                    .protocol_config
                    .max_trans_count_received_in_catch_up
                    as usize
            {
                bail!(ErrorKind::TooManyTrans);
            }
        }

        ctx.manager.request_manager.request_transactions(
            ctx.io,
            ctx.peer,
            self.window_index,
            &self.trans_short_ids,
        );

        Ok(())
    }
}

impl Message for TransactionDigests {
    fn msg_id(&self) -> MsgId { MsgId::TRANSACTION_DIGESTS }

    fn is_size_sensitive(&self) -> bool { self.trans_short_ids.len() > 1 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

impl Encodable for TransactionDigests {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(2)
            .append(&self.window_index)
            .append_list(&self.trans_short_ids);
    }
}

impl Decodable for TransactionDigests {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(TransactionDigests {
            window_index: rlp.val_at(0)?,
            trans_short_ids: rlp.list_at(1)?,
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

impl Request for GetTransactions {
    fn set_request_id(&mut self, request_id: u64) {
        self.request_id.set_request_id(request_id);
    }

    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.transaction_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        for tx_id in self.tx_ids.iter() {
            inflight_keys.remove(msg_type, Key::Id(*tx_id));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();

        let mut tx_ids: HashSet<TxPropagateId> = HashSet::new();
        for id in self.tx_ids.iter() {
            if inflight_keys.add(msg_type, Key::Id(*id)) {
                tx_ids.insert(*id);
            }
        }

        self.tx_ids = tx_ids;
    }

    fn is_empty(&self) -> bool { self.tx_ids.is_empty() }

    fn resend(&self) -> Option<Box<Request>> { None }
}

impl Handleable for GetTransactions {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions = ctx
            .manager
            .request_manager
            .get_sent_transactions(&self.indices);
        let response = GetTransactionsResponse {
            request_id: self.request_id.clone(),
            transactions,
        };
        debug!(
            "on_get_transactions request {} txs, returned {} txs",
            self.indices.len(),
            response.transactions.len()
        );

        ctx.send_response(&response)
    }
}

impl Message for GetTransactions {
    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
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

impl Handleable for GetTransactionsResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(TX_HANDLE_TIMER.as_ref());

        debug!("on_get_transactions_response {:?}", self.request_id());

        let req = ctx.match_request(self.request_id())?;
        let req = req.downcast_general::<GetTransactions>(
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

        ctx.manager
            .request_manager
            .transactions_received(&req.tx_ids);

        let (signed_trans, _) = ctx
            .manager
            .graph
            .consensus
            .txpool
            .insert_new_transactions(&self.transactions);

        ctx.manager
            .request_manager
            .append_received_transactions(signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }
}

impl Message for GetTransactionsResponse {
    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
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
