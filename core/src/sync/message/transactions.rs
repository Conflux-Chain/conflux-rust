// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    sync::{
        message::{
            metrics::TX_HANDLE_TIMER, msgid, Context, DynamicCapability,
            Handleable, Key, KeyContainer,
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
use siphasher::sip::SipHasher24;
use std::{collections::HashSet, hash::Hasher, time::Duration};

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
    pub key1: u64, //keys used for siphash
    pub key2: u64,
    short_ids: Vec<u8>, // 4 bytes ids which stores in sequential order
    pub tx_hashes: Vec<H256>, // SHA-3 hash
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
                    self.short_ids.len() + self.tx_hashes.len();
                if peer_info.received_transaction_count
                    > ctx
                        .manager
                        .protocol_config
                        .max_trans_count_received_in_catch_up
                        as usize
                {
                    bail!(ErrorKind::TooManyTrans);
                }
                if self.short_ids.len() % Self::SHORT_ID_SIZE_IN_BYTES != 0 {
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
        if self.tx_hashes.is_empty() {
            stream
                .begin_list(4)
                .append(&self.window_index)
                .append(&self.key1)
                .append(&self.key2)
                .append(&self.short_ids);
        } else {
            stream
                .begin_list(5)
                .append(&self.window_index)
                .append(&self.key1)
                .append(&self.key2)
                .append(&self.short_ids)
                .append_list(&self.tx_hashes);
        }
    }
}

impl Decodable for TransactionDigests {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !(rlp.item_count()? == 4 || rlp.item_count()? == 5) {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let short_ids: Vec<u8> = rlp.val_at(3)?;
        if short_ids.len() % TransactionDigests::SHORT_ID_SIZE_IN_BYTES != 0 {
            return Err(DecoderError::Custom(
                "TransactionDigests length Error!",
            ));
        }

        let tx_hashes = {
            if rlp.item_count()? == 5 {
                rlp.list_at(4)?
            } else {
                vec![]
            }
        };

        Ok(TransactionDigests {
            window_index: rlp.val_at(0)?,
            key1: rlp.val_at(1)?,
            key2: rlp.val_at(2)?,
            short_ids,
            tx_hashes,
        })
    }
}

impl TransactionDigests {
    const SHORT_ID_SIZE_IN_BYTES: usize = 4;

    pub fn new(
        window_index: usize, key1: u64, key2: u64, short_ids: Vec<u8>,
        tx_hashes: Vec<H256>,
    ) -> TransactionDigests
    {
        TransactionDigests {
            window_index,
            key1,
            key2,
            short_ids,
            tx_hashes,
        }
    }

    pub fn get_decomposed_short_ids(&self) -> (Vec<u8>, Vec<TxPropagateId>) {
        let mut random_byte_vector: Vec<u8> = Vec::new();
        let mut fixed_bytes_vector: Vec<TxPropagateId> = Vec::new();

        for i in (0..self.short_ids.len())
            .step_by(TransactionDigests::SHORT_ID_SIZE_IN_BYTES)
        {
            random_byte_vector.push(self.short_ids[i]);
            fixed_bytes_vector.push(TransactionDigests::to_u24(
                self.short_ids[i + 1],
                self.short_ids[i + 2],
                self.short_ids[i + 3],
            ));
        }

        (random_byte_vector, fixed_bytes_vector)
    }

    pub fn len(&self) -> usize {
        self.short_ids.len() / TransactionDigests::SHORT_ID_SIZE_IN_BYTES
    }

    pub fn to_u24(v1: u8, v2: u8, v3: u8) -> u32 {
        ((v1 as u32) << 16) + ((v2 as u32) << 8) + v3 as u32
    }

    pub fn append_short_id(
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

    pub fn append_tx_hash(message: &mut Vec<H256>, transaction_id: H256) {
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
    pub tx_hashes_indices: Vec<usize>,
    pub short_ids: HashSet<TxPropagateId>,
    pub tx_hashes: HashSet<H256>,
}

impl Request for GetTransactions {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.transaction_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut short_id_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut tx_hash_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);
        for tx in &self.short_ids {
            short_id_inflight_keys.remove(&Key::Id(*tx));
        }
        for tx in &self.tx_hashes {
            tx_hash_inflight_keys.remove(&Key::Hash(*tx));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut short_id_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut tx_hash_inflight_keys =
            inflight_keys.write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);
        let mut short_ids: HashSet<TxPropagateId> = HashSet::new();
        let mut tx_hashes: HashSet<H256> = HashSet::new();
        for id in self.short_ids.iter() {
            if short_id_inflight_keys.insert(Key::Id(*id)) {
                short_ids.insert(*id);
            }
        }
        for id in self.tx_hashes.iter() {
            if tx_hash_inflight_keys.insert(Key::Hash(*id)) {
                tx_hashes.insert(*id);
            }
        }

        self.short_ids = short_ids;
        self.tx_hashes = tx_hashes;
    }

    fn is_empty(&self) -> bool {
        self.tx_hashes_indices.is_empty() && self.indices.is_empty()
    }

    fn resend(&self) -> Option<Box<dyn Request>> { None }
}

impl Handleable for GetTransactions {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions = ctx
            .manager
            .request_manager
            .get_sent_transactions(self.window_index, &self.indices);
        let tx_hashes_indices = ctx
            .manager
            .request_manager
            .get_sent_transactions(self.window_index, &self.tx_hashes_indices);
        let tx_hashes =
            tx_hashes_indices.into_iter().map(|tx| tx.hash()).collect();
        let response = GetTransactionsResponse {
            request_id: self.request_id,
            transactions,
            tx_hashes,
        };
        debug!(
            "on_get_transactions request {} txs, {} tx hashes, returned {} txs {} tx hashes",
            self.indices.len(),
            self.tx_hashes_indices.len(),
            response.transactions.len(),
            response.tx_hashes.len(),
        );

        ctx.send_response(&response)
    }
}

impl Encodable for GetTransactions {
    fn rlp_append(&self, stream: &mut RlpStream) {
        if self.tx_hashes_indices.is_empty() {
            stream
                .begin_list(3)
                .append(&self.request_id)
                .append(&self.window_index)
                .append_list(&self.indices);
        } else {
            stream
                .begin_list(4)
                .append(&self.request_id)
                .append(&self.window_index)
                .append_list(&self.indices)
                .append_list(&self.tx_hashes_indices);
        }
    }
}

impl Decodable for GetTransactions {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !(rlp.item_count()? == 3 || rlp.item_count()? == 4) {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        if rlp.item_count()? == 3 {
            Ok(GetTransactions {
                request_id: rlp.val_at(0)?,
                window_index: rlp.val_at(1)?,
                indices: rlp.list_at(2)?,
                tx_hashes_indices: vec![],
                short_ids: HashSet::new(),
                tx_hashes: HashSet::new(),
            })
        } else {
            Ok(GetTransactions {
                request_id: rlp.val_at(0)?,
                window_index: rlp.val_at(1)?,
                indices: rlp.list_at(2)?,
                tx_hashes_indices: rlp.list_at(3)?,
                short_ids: HashSet::new(),
                tx_hashes: HashSet::new(),
            })
        }
    }
}

/////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct GetTransactionsFromTxHashes {
    pub request_id: RequestId,
    pub window_index: usize,
    pub indices: Vec<usize>,
    pub tx_hashes: HashSet<H256>,
}

impl Request for GetTransactionsFromTxHashes {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.transaction_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        for tx_hash in self.tx_hashes.iter() {
            inflight_keys.remove(&Key::Hash(*tx_hash));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());

        let mut tx_hashes: HashSet<H256> = HashSet::new();
        for id in self.tx_hashes.iter() {
            if inflight_keys.insert(Key::Hash(*id)) {
                tx_hashes.insert(*id);
            }
        }

        self.tx_hashes = tx_hashes;
    }

    fn is_empty(&self) -> bool { self.tx_hashes.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> { None }
}

impl Handleable for GetTransactionsFromTxHashes {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions = ctx
            .manager
            .request_manager
            .get_sent_transactions(self.window_index, &self.indices);

        let response = GetTransactionsFromTxHashesResponse {
            request_id: self.request_id,
            transactions,
        };
        debug!(
            "on_get_transactions_from_tx_hashes request {} txs, returned {} txs",
            self.indices.len(),
            response.transactions.len(),
        );

        ctx.send_response(&response)
    }
}

impl Encodable for GetTransactionsFromTxHashes {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(3)
            .append(&self.request_id)
            .append(&self.window_index)
            .append_list(&self.indices);
    }
}

impl Decodable for GetTransactionsFromTxHashes {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(GetTransactionsFromTxHashes {
            request_id: rlp.val_at(0)?,
            window_index: rlp.val_at(1)?,
            indices: rlp.list_at(2)?,
            tx_hashes: HashSet::new(),
        })
    }
}

///////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct GetTransactionsResponse {
    pub request_id: RequestId,
    pub transactions: Vec<TransactionWithSignature>,
    pub tx_hashes: Vec<H256>,
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
            "Received {:?} transactions and {:?} tx hashes from Peer {:?}",
            self.transactions.len(),
            self.tx_hashes.len(),
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

        if req.tx_hashes_indices.len() > 0 && !self.tx_hashes.is_empty() {
            ctx.manager
                .request_manager
                .request_transactions_from_tx_hashes(
                    ctx.io,
                    ctx.peer,
                    self.tx_hashes,
                    req.window_index,
                    &req.tx_hashes_indices,
                );
        }
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, RlpDecodable, RlpEncodable)]
pub struct GetTransactionsFromTxHashesResponse {
    pub request_id: RequestId,
    pub transactions: Vec<TransactionWithSignature>,
}

impl Handleable for GetTransactionsFromTxHashesResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let _timer = MeterTimer::time_func(TX_HANDLE_TIMER.as_ref());

        debug!(
            "on_get_transactions_from_tx_hashes_response {:?}",
            self.request_id
        );

        let req = ctx.match_request(self.request_id)?;
        let req = req.downcast_ref::<GetTransactionsFromTxHashes>(
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
            .transactions_received_from_tx_hashes(&req, signed_trans);

        debug!("Transactions successfully inserted to transaction pool");
        Ok(())
    }
}
