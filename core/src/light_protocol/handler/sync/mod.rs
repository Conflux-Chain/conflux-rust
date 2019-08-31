// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod blooms;
mod epochs;
mod headers;
mod sync_manager;
mod witnesses;

use rlp::Rlp;
use std::sync::Arc;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{Peers, UniqueId},
        handler::FullPeerState,
        message::{
            BlockHashes as GetBlockHashesResponse,
            BlockHeaders as GetBlockHeadersResponse,
            Blooms as GetBloomsResponse, NewBlockHashes,
            WitnessInfo as GetWitnessInfoResponse,
        },
        Error,
    },
    network::{NetworkContext, PeerId},
    parameters::light::CATCH_UP_EPOCH_LAG_THRESHOLD,
    sync::SynchronizationGraph,
};

use blooms::Blooms;
use epochs::Epochs;
use headers::{HashSource, Headers};
use witnesses::Witnesses;

#[derive(Debug)]
struct Statistics {
    catch_up_mode: bool,
    latest_epoch: u64,
}

pub(super) struct SyncHandler {
    // bloom sync manager
    blooms: Arc<Blooms>,

    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // epoch sync manager
    epochs: Epochs,

    // header sync manager
    headers: Arc<Headers>,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,

    // witness sync manager
    witnesses: Witnesses,
}

impl SyncHandler {
    pub(super) fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
        request_id_allocator: Arc<UniqueId>, peers: Arc<Peers<FullPeerState>>,
    ) -> Self
    {
        // TODO(thegaram): At this point the light node does not persist
        // anything. Need to make sure we persist the checkpoint hashes,
        // along with a Merkle-root for headers in each era.
        graph.recover_graph_from_db(true /* header_only */);

        let headers = Arc::new(Headers::new(
            graph.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        ));

        let epochs = Epochs::new(
            consensus.clone(),
            headers.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        );

        let blooms = Arc::new(Blooms::new(
            consensus.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        ));

        let witnesses = Witnesses::new(
            blooms.clone(),
            consensus.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        );

        SyncHandler {
            blooms,
            consensus,
            epochs,
            headers,
            peers,
            witnesses,
        }
    }

    #[inline]
    pub fn median_peer_epoch(&self) -> Option<u64> {
        let mut best_epochs = self.peers.fold(vec![], |mut res, state| {
            res.push(state.read().best_epoch);
            res
        });

        best_epochs.sort();

        match best_epochs.len() {
            0 => None,
            n => Some(best_epochs[n / 2]),
        }
    }

    #[inline]
    fn catch_up_mode(&self) -> bool {
        match self.median_peer_epoch() {
            None => true,
            Some(epoch) => {
                let my_epoch = self.consensus.best_epoch_number();
                my_epoch + CATCH_UP_EPOCH_LAG_THRESHOLD < epoch
            }
        }
    }

    #[inline]
    fn get_statistics(&self) -> Statistics {
        Statistics {
            catch_up_mode: self.catch_up_mode(),
            latest_epoch: self.consensus.best_epoch_number(),
        }
    }

    #[inline]
    fn collect_terminals(&self) {
        let terminals = self.peers.fold(vec![], |mut res, state| {
            let mut state = state.write();
            res.extend(state.terminals.iter());
            state.terminals.clear();
            res
        });

        let terminals = terminals.into_iter();
        self.headers.request(terminals, HashSource::NewHash);
    }

    pub(super) fn on_block_hashes(
        &self, io: &dyn NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockHashesResponse = rlp.as_val()?;
        info!("on_block_hashes resp={:?}", resp);

        self.epochs.receive(&resp.request_id);

        let hashes = resp.hashes.into_iter();
        self.headers.request(hashes, HashSource::Epoch);

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_block_headers(
        &self, io: &dyn NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockHeadersResponse = rlp.as_val()?;
        info!("on_block_headers resp={:?}", resp);

        self.headers.receive(resp.headers.into_iter());

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_new_block_hashes(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let msg: NewBlockHashes = rlp.as_val()?;
        info!("on_new_block_hashes msg={:?}", msg);

        if self.catch_up_mode() {
            if let Some(state) = self.peers.get(&peer) {
                let mut state = state.write();
                state.terminals.extend(msg.hashes);
            }
            return Ok(());
        }

        let hashes = msg.hashes.into_iter();
        self.headers.request(hashes, HashSource::NewHash);

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_witness_info(
        &self, io: &dyn NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetWitnessInfoResponse = rlp.as_val()?;
        info!("on_witness_info resp={:?}", resp);

        self.witnesses.receive(resp.infos.into_iter())?;

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_blooms(
        &self, io: &dyn NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBloomsResponse = rlp.as_val()?;
        info!("on_blooms resp={:?}", resp);

        self.blooms.receive(resp.blooms.into_iter())?;

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn start_sync(&self, io: &dyn NetworkContext) {
        info!("general sync statistics: {:?}", self.get_statistics());

        match self.catch_up_mode() {
            true => {
                self.headers.sync(io);
                self.epochs.sync(io);
                self.witnesses.sync(io);
                self.blooms.sync(io);
            }
            false => {
                self.collect_terminals();
                self.headers.sync(io);
                self.witnesses.sync(io);
                self.blooms.sync(io);
            }
        };
    }

    pub(super) fn clean_up_requests(&self) {
        info!("clean_up_requests");
        self.blooms.clean_up();
        self.epochs.clean_up();
        self.headers.clean_up();
        self.witnesses.clean_up();
    }
}
