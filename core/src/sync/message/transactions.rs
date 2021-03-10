// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{
        GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId,
        RequestId, SetRequestId,
    },
    sync::{
        message::{
            metrics::TX_HANDLE_TIMER, msgid, Context, DynamicCapability,
            Handleable, Key, KeyContainer,
        },
        request_manager::{AsAny, Request},
        Error, ErrorKind, ProtocolConfiguration, SYNC_PROTO_V1, SYNC_PROTO_V3,
    },
};
use cfx_types::H256;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::MeterTimer;
use network::service::ProtocolVersion;
use primitives::{transaction::TxPropagateId, TransactionWithSignature};
use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use siphasher::sip::SipHasher24;
use std::{any::Any, collections::HashSet, hash::Hasher, time::Duration};

#[derive(Debug, PartialEq)]
pub struct Transactions {
    pub transactions: Vec<TransactionWithSignature>,
}

impl Encodable for Transactions {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_list(&self.transactions);
    }
}

impl Decodable for Transactions {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        let transactions = d.as_list()?;
        Ok(Transactions { transactions })
    }
}

impl Handleable for Transactions {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let transactions = self.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            ctx.node_id
        );

        let peer_info = ctx.manager.syn.get_peer_info(&ctx.node_id)?;
        let should_disconnect = {
            let mut peer_info = peer_info.write();
            if peer_info
                .notified_capabilities
                .contains(DynamicCapability::NormalPhase(false))
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

        // The transaction pool will rely on the execution state information to
        // verify transaction validity. It may incorrectly accept/reject
        // transactions when in the catch up mode because the state is still
        // not correct. We therefore do not insert transactions when in the
        // catch up mode.
        if !ctx.manager.catch_up_mode() {
            let (signed_trans, failure) = ctx
                .manager
                .graph
                .consensus
                .get_tx_pool()
                .insert_new_transactions(transactions);
            if failure.is_empty() {
                debug!(
                    "Transactions successfully inserted to transaction pool"
                );
            } else {
                debug!(
                    "{} transactions are rejected by the transaction pool",
                    failure.len()
                );
                for (tx, e) in failure {
                    trace!("Transaction {} is rejected by the transaction pool: error = {}", tx, e);
                }
            }

            ctx.manager
                .request_manager
                .append_received_transactions(signed_trans);
            Ok(())
        } else {
            debug!("All {} transactions are not inserted to the transaction pool, because the node is still in the catch up mode", transactions.len());
            Err(ErrorKind::InCatchUpMode("ignore transaction_digests message because still in the catch up mode".to_string()).into())
        }
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
            let peer_info = ctx.manager.syn.get_peer_info(&ctx.node_id)?;

            let mut peer_info = peer_info.write();
            if peer_info
                .notified_capabilities
                .contains(DynamicCapability::NormalPhase(false))
            {
                peer_info.received_transaction_count += self.short_ids.len()
                    / Self::SHORT_ID_SIZE_IN_BYTES
                    + self.tx_hashes.len();
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
        }

        // We will not request transactions when in the catch up mode, because
        // the transaction pool cannot process them correctly.
        if !ctx.manager.catch_up_mode() {
            ctx.manager
                .request_manager
                .request_transactions_from_digest(
                    ctx.io,
                    ctx.node_id.clone(),
                    &self,
                );
            Ok(())
        } else {
            Err(ErrorKind::InCatchUpMode("ignore transaction_digests message because still in the catch up mode".to_string()).into())
        }
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

#[derive(Debug, PartialEq, DeriveMallocSizeOf)]
pub struct GetTransactions {
    pub request_id: RequestId,
    pub window_index: usize,
    pub indices: Vec<usize>,
    pub tx_hashes_indices: Vec<usize>,
    pub short_ids: HashSet<TxPropagateId>,
    pub tx_hashes: HashSet<H256>,
}

impl_request_id_methods!(GetTransactions);

impl AsAny for GetTransactions {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

mark_msg_version_bound!(GetTransactions, SYNC_PROTO_V1, SYNC_PROTO_V3);
impl Message for GetTransactions {
    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS }

    fn msg_name(&self) -> &'static str { "GetTransactions" }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
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

#[derive(Debug, PartialEq, DeriveMallocSizeOf)]
pub struct GetTransactionsFromTxHashes {
    pub request_id: RequestId,
    pub window_index: usize,
    pub indices: Vec<usize>,
    pub tx_hashes: HashSet<H256>,
}

impl_request_id_methods!(GetTransactionsFromTxHashes);

impl AsAny for GetTransactionsFromTxHashes {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

mark_msg_version_bound!(
    GetTransactionsFromTxHashes,
    SYNC_PROTO_V1,
    SYNC_PROTO_V3
);
impl Message for GetTransactionsFromTxHashes {
    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS_FROM_TX_HASHES }

    fn msg_name(&self) -> &'static str { "GetTransactionsFromTxHashes" }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
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
        )?;

        // FIXME: Do some check based on transaction request.

        debug!(
            "Received {:?} transactions and {:?} tx hashes from Peer {:?}",
            self.transactions.len(),
            self.tx_hashes.len(),
            ctx.node_id
        );

        // The transaction pool will rely on the execution state information to
        // verify transaction validity. It may incorrectly accept/reject
        // transactions when in the catch up mode because the state is still
        // not correct. We therefore do not insert transactions when in the
        // catch up mode.
        if !ctx.manager.catch_up_mode() {
            let (signed_trans, failure) = ctx
                .manager
                .graph
                .consensus
                .get_tx_pool()
                .insert_new_transactions(self.transactions);
            if failure.is_empty() {
                debug!(
                    "Transactions successfully inserted to transaction pool"
                );
            } else {
                debug!(
                    "{} transactions are rejected by the transaction pool",
                    failure.len()
                );
                for (tx, e) in failure {
                    trace!("Transaction {} is rejected by the transaction pool: error = {}", tx, e);
                }
            }
            ctx.manager
                .request_manager
                .transactions_received_from_digests(ctx.io, &req, signed_trans);

            if req.tx_hashes_indices.len() > 0 && !self.tx_hashes.is_empty() {
                ctx.manager
                    .request_manager
                    .request_transactions_from_tx_hashes(
                        ctx.io,
                        ctx.node_id.clone(),
                        self.tx_hashes,
                        req.window_index,
                        &req.tx_hashes_indices,
                    );
            }
            Ok(())
        } else {
            debug!("All {} transactions are not inserted to the transaction pool, because the node is still in the catch up mode", self.transactions.len());
            Err(ErrorKind::InCatchUpMode("transactions discarded for handling on_get_transactions_response messages".to_string()).into())
        }
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
        )?;

        // FIXME: Do some check based on transaction request.

        debug!(
            "Received {:?} transactions from Peer {:?}",
            self.transactions.len(),
            ctx.node_id
        );

        // The transaction pool will rely on the execution state information to
        // verify transaction validity. It may incorrectly accept/reject
        // transactions when in the catch up mode because the state is still
        // not correct. We therefore do not insert transactions when in the
        // catch up mode.
        if !ctx.manager.catch_up_mode() {
            let (signed_trans, failure) = ctx
                .manager
                .graph
                .consensus
                .get_tx_pool()
                .insert_new_transactions(self.transactions);
            if failure.is_empty() {
                debug!(
                    "Transactions successfully inserted to transaction pool"
                );
            } else {
                debug!(
                    "{} transactions are rejected by the transaction pool",
                    failure.len()
                );
                for (tx, e) in failure {
                    trace!("Transaction {} is rejected by the transaction pool: error = {}", tx, e);
                }
            }
            ctx.manager
                .request_manager
                .transactions_received_from_tx_hashes(&req, signed_trans);
            Ok(())
        } else {
            debug!("All {} transactions are not inserted to the transaction pool, because the node is still in the catch up mode", self.transactions.len());
            Err(ErrorKind::InCatchUpMode("transactions discarded for handling on_get_transactions_response messages".to_string()).into())
        }
    }
}
