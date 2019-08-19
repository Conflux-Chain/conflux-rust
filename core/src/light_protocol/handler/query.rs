// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::RwLock;
use rlp::Rlp;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

extern crate futures;
use futures::{
    sync::oneshot::{self, Sender},
    Async, Future,
};

use cfx_types::H256;
use primitives::{BlockHeader, BlockHeaderBuilder, EpochNumber, StateRoot};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        message::{
            GetStateEntry, GetStateRoot, StateEntry as GetStateEntryResponse,
            StateRoot as GetStateRootResponse, StateRootWithProof,
        },
        Error, ErrorKind,
    },
    message::{HasRequestId, Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{MAX_POLL_TIME_MS, POLL_PERIOD_MS},
    },
};

#[derive(Debug)]
pub enum QueryResult {
    StateEntry(Option<Vec<u8>>),
    StateRoot(StateRoot),
}

struct PendingRequest {
    msg: Box<dyn Message>,
    sender: Sender<QueryResult>,
}

pub struct QueryHandler {
    consensus: Arc<ConsensusGraph>,
    next_request_id: Arc<AtomicU64>,
    pending: RwLock<BTreeMap<(PeerId, RequestId), PendingRequest>>,
}

impl QueryHandler {
    pub fn new(
        consensus: Arc<ConsensusGraph>, next_request_id: Arc<AtomicU64>,
    ) -> Self {
        QueryHandler {
            consensus,
            next_request_id,
            pending: RwLock::new(BTreeMap::new()),
        }
    }

    #[inline]
    fn pivot_hash_of(&self, epoch: u64) -> Result<H256, Error> {
        let epoch = EpochNumber::Number(epoch);
        Ok(self.consensus.get_hash_from_epoch_number(epoch)?)
    }

    #[inline]
    fn pivot_header_of(&self, epoch: u64) -> Result<Arc<BlockHeader>, Error> {
        let pivot = self.pivot_hash_of(epoch)?;
        let header = self.consensus.data_man.block_header_by_hash(&pivot);
        header.ok_or(ErrorKind::InternalError.into())
    }

    fn validate_pivot_hash(&self, epoch: u64, hash: H256) -> Result<(), Error> {
        match self.pivot_hash_of(epoch)? {
            h if h == hash => Ok(()),
            h => {
                // NOTE: this can happen in normal scenarios
                // where the pivot chain has not converged
                debug!("Pivot hash mismatch: local={}, response={}", h, hash);
                Err(ErrorKind::PivotHashMismatch.into())
            }
        }
    }

    // 1. When validating a state root, we first find the witness - the block
    //    header that can be used to verify the state root. This selection is
    //    done based on the blame fields.
    // 2. Then we validate the integrity of the provided hash set against the
    //    deferred state root field of the witness.
    // 3. Finally, we validate the state root against the corresponding state
    //    root hash provided.
    fn validate_state_root(
        &self, epoch: u64, state_root: &StateRootWithProof,
    ) -> Result<(), Error> {
        // find the first header that can verify the state root requested
        let witness = self.consensus.first_epoch_with_correct_state_of(epoch);

        let witness = match witness {
            Some(epoch) => epoch,
            None => {
                warn!("Unable to verify state proof for epoch {}", epoch);
                return Err(ErrorKind::UnableToProduceProof.into());
            }
        };

        let witness_header = self.pivot_header_of(witness)?;
        let blame = witness_header.blame() as u64;

        // assumption: the target state root can be verified by the witness
        assert!(witness <= epoch + DEFERRED_STATE_EPOCH_COUNT + blame);

        // validate the number of hashes provided against local witness blame
        if state_root.proof.len() as u64 != blame + 1 {
            info!(
                "Invalid number of hashes provided: expected={}, received={}",
                blame + 1,
                state_root.proof.len()
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        // compute witness deferred state root hash from the hashes provided
        let received_witness_root_hash = match blame {
            0 => state_root.proof[0],
            _ => {
                let hashes = state_root.proof.clone();
                BlockHeaderBuilder::compute_blame_state_root_vec_root(hashes)
            }
        };

        // validate against local witness deferred state root hash
        let local_witness_root_hash = *witness_header.deferred_state_root();

        if received_witness_root_hash != local_witness_root_hash {
            info!(
                "Witness root hash mismatch: local={}, received={}",
                local_witness_root_hash, received_witness_root_hash
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        // TODO(thegaram): at this point, we can cache all the hashes received
        // and reuse them later

        // find hash corresponding to the state root requested
        let index = (witness - epoch - DEFERRED_STATE_EPOCH_COUNT) as usize;
        let received_root_hash = state_root.proof[index];

        // validate state root against the hash provided
        let computed_root_hash = state_root.root.compute_state_root_hash();

        if received_root_hash != computed_root_hash {
            info!(
                "State root hash mismatch: received={}, computed={}",
                received_root_hash, computed_root_hash
            );
            return Err(ErrorKind::InvalidStateRoot.into());
        }

        Ok(())
    }

    fn next_request_id(&self) -> RequestId {
        self.next_request_id.fetch_add(1, Ordering::Relaxed).into()
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

        self.validate_pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate_state_root(req.epoch, &resp.state_root)?;

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

        self.validate_pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate_state_root(req.epoch, &resp.state_root)?;

        // validate proof
        if !resp.proof.is_valid(
            &req.key,
            resp.entry.as_ref().map(|v| &**v),
            resp.state_root.root.delta_root,
            resp.state_root.root.intermediate_delta_root,
            resp.state_root.root.snapshot_root,
        ) {
            info!("Invalid proof from peer={}", peer);
            return Err(ErrorKind::InvalidProof.into());
        }

        sender.complete(QueryResult::StateEntry(resp.entry));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    /// Send `req` to `peer` and wait for result.
    pub fn execute<T>(
        &self, io: &dyn NetworkContext, peer: PeerId, mut req: T,
    ) -> Result<QueryResult, Error>
    where T: Message + HasRequestId + Clone + 'static {
        // set request id
        let id = self.next_request_id();
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

        Err(ErrorKind::NoResponse.into())
    }
}
