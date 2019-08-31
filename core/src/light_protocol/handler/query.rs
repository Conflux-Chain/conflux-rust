// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::RwLock;
use rlp::Rlp;
use std::{collections::BTreeMap, sync::Arc};

extern crate futures;
use futures::{
    sync::oneshot::{self, Sender},
    Async, Future,
};

use primitives::{Receipt, SignedTransaction, StateRoot};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{UniqueId, Validate},
        message::{
            GetReceipts, GetStateEntry, GetStateRoot, GetTxs,
            Receipts as GetReceiptsResponse,
            StateEntry as GetStateEntryResponse,
            StateRoot as GetStateRootResponse, Txs as GetTxsResponse,
        },
        Error, ErrorKind,
    },
    message::{HasRequestId, Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{MAX_POLL_TIME_MS, POLL_PERIOD_MS},
};

#[derive(Debug)]
pub enum QueryResult {
    StateEntry(Option<Vec<u8>>),
    StateRoot(StateRoot),
    Receipts(Vec<Vec<Receipt>>),
    Txs(Vec<SignedTransaction>),
}

struct PendingRequest {
    msg: Box<dyn Message>,
    sender: Sender<QueryResult>,
}

pub struct QueryHandler {
    // set of queries sent but not received yet
    pending: RwLock<BTreeMap<(PeerId, RequestId), PendingRequest>>,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // helper API for validating ledger and state information
    validate: Validate,
}

impl QueryHandler {
    pub fn new(
        consensus: Arc<ConsensusGraph>, request_id_allocator: Arc<UniqueId>,
    ) -> Self {
        let pending = RwLock::new(BTreeMap::new());
        let validate = Validate::new(consensus.clone());

        QueryHandler {
            pending,
            request_id_allocator,
            validate,
        }
    }

    fn match_request<T>(
        &self, peer: PeerId, id: RequestId,
    ) -> Result<(T, Sender<QueryResult>), Error>
    where T: Message + Clone + 'static {
        let (msg, sender) = match self.pending.write().remove(&(peer, id)) {
            Some(PendingRequest { msg, sender }) => (msg, sender),
            None => {
                warn!("Unexpected request id: {:?}", id);
                return Err(ErrorKind::UnexpectedRequestId.into());
            }
        };

        match msg.as_any().downcast_ref::<T>() {
            Some(req) => Ok(((*req).clone(), sender)),
            None => {
                warn!("Unexpected response type from peer={}", peer);
                Err(ErrorKind::UnexpectedResponse.into())
            }
        }
    }

    pub(super) fn on_state_root(
        &self, _io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetStateRootResponse = rlp.as_val()?;
        info!("on_state_root resp={:?}", resp);

        let id = resp.request_id;
        let (req, sender) = self.match_request::<GetStateRoot>(peer, id)?;

        self.validate.pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate.state_root(req.epoch, &resp.state_root)?;

        sender.complete(QueryResult::StateRoot(resp.state_root.root));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    pub(super) fn on_state_entry(
        &self, _io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetStateEntryResponse = rlp.as_val()?;
        info!("on_state_entry resp={:?}", resp);

        let id = resp.request_id;
        let (req, sender) = self.match_request::<GetStateEntry>(peer, id)?;

        self.validate.pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate.state_root(req.epoch, &resp.state_root)?;

        // validate proof
        let key = &req.key;
        let value = resp.entry.as_ref().map(|v| &**v);
        let root = resp.state_root.root;

        if !resp.proof.is_valid_kv(key, value, root) {
            info!("Invalid proof from peer={}", peer);
            return Err(ErrorKind::InvalidStateProof.into());
        }

        sender.complete(QueryResult::StateEntry(resp.entry));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    pub(super) fn on_receipts(
        &self, _io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetReceiptsResponse = rlp.as_val()?;
        info!("on_receipts resp={:?}", resp);

        let id = resp.request_id;
        let (req, sender) = self.match_request::<GetReceipts>(peer, id)?;

        self.validate.pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate.receipts(req.epoch, &resp.receipts)?;

        sender.complete(QueryResult::Receipts(resp.receipts.receipts));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    pub(super) fn on_txs(
        &self, _io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetTxsResponse = rlp.as_val()?;
        info!("on_txs resp={:?}", resp);

        let id = resp.request_id;
        let (_req, sender) = self.match_request::<GetTxs>(peer, id)?;

        self.validate.txs(&resp.txs)?;

        sender.complete(QueryResult::Txs(resp.txs));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    /// Send `req` to `peer` and wait for result.
    pub fn execute<T>(
        &self, io: &dyn NetworkContext, peer: PeerId, mut req: T,
    ) -> Result<QueryResult, Error>
    where T: Message + HasRequestId + Clone + 'static {
        // set request id
        let id = self.request_id_allocator.next();
        req.set_request_id(id);

        // set up channel and store request
        let mut receiver = {
            let msg: Box<dyn Message> = Box::new(req.clone());
            let (sender, receiver) = oneshot::channel();
            let pending = PendingRequest { msg, sender };
            self.pending.write().insert((peer, id), pending);
            receiver
        };

        // send request
        let msg: Box<dyn Message> = Box::new(req);
        msg.send(io, peer)?;

        // poll result
        // TODO(thegaram): come up with something better
        // we can consider returning a future if it is
        // compatible with our current event loop
        let max_poll_num = MAX_POLL_TIME_MS / POLL_PERIOD_MS;

        for _ in 0..max_poll_num {
            match receiver.poll() {
                Ok(Async::Ready(resp)) => return Ok(resp),
                Ok(Async::NotReady) => (),
                Err(_) => return Err(ErrorKind::ValidationFailed.into()),
            }

            let d = std::time::Duration::from_millis(POLL_PERIOD_MS);
            std::thread::sleep(d);
        }

        // TODO(thegaram): remove timeout requests from `pending`
        Err(ErrorKind::NoResponse.into())
    }
}
