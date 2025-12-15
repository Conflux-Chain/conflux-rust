// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
mod assembler;
mod mine_session;
mod miner;
mod test_api;

pub use crate::test_api::BlockGeneratorTestApi;

use crate::{
    assembler::BlockAssembler, mine_session::MiningSession, miner::MineWorker,
};

use cfx_types::Address;
use cfxcore::{
    consensus::pos_handler::PosVerifier, pow::*, ConsensusGraph,
    SharedSynchronizationGraph, SharedSynchronizationService,
    SharedTransactionPool, Stopable,
};
use parking_lot::RwLock;
use primitives::Block;
use std::sync::{mpsc, Arc};
use txgen::SharedTransactionGenerator;

enum MiningStatus {
    Start,
    Stop,
}

type SolutionReceiver = mpsc::Receiver<ProofOfWorkSolution>;

/// The interface for a conflux block generator
pub struct BlockGenerator {
    pub(crate) pow_config: ProofOfWorkConfig,
    pub(crate) pow: Arc<PowComputer>,
    consensus: Arc<ConsensusGraph>,
    sync: SharedSynchronizationService,
    status: RwLock<MiningStatus>,
    assembler: BlockAssembler,
}

impl BlockGenerator {
    pub fn new(
        graph: SharedSynchronizationGraph, txpool: SharedTransactionPool,
        sync: SharedSynchronizationService,
        maybe_txgen: Option<SharedTransactionGenerator>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        mining_author: Address, pos_verifier: Arc<PosVerifier>,
    ) -> Self {
        let consensus = graph.consensus.clone();
        let assembler = BlockAssembler::new(
            graph,
            txpool,
            maybe_txgen,
            mining_author,
            pos_verifier,
        );
        BlockGenerator {
            pow_config,
            pow,
            consensus,
            sync,
            assembler,
            status: RwLock::new(MiningStatus::Start),
        }
    }

    fn is_running(&self) -> bool {
        matches!(*self.status.read(), MiningStatus::Start)
    }

    /// Stop mining
    pub fn stop(&self) {
        {
            let mut write = self.status.write();
            *write = MiningStatus::Stop;
        }
        self.assembler.stop();
    }

    /// Update and sync a new block
    fn on_mined_block(&self, block: Block) {
        // FIXME: error handling.
        self.sync.on_mined_block(block).ok();
    }

    pub fn test_api(self: &Arc<Self>) -> BlockGeneratorTestApi {
        BlockGeneratorTestApi::new(self.clone())
    }

    pub fn mine(self: &Arc<Self>) {
        let miner_type = if self.pow_config.use_stratum() {
            miner::MinerType::Stratum
        } else {
            miner::MinerType::Cpu(1)
        };

        let (miner, solution_rx) = miner::spawn(self.clone(), miner_type);

        MiningSession::new(&*self, &*miner, solution_rx).run();
    }
}

impl Stopable for BlockGenerator {
    fn stop(&self) { BlockGenerator::stop(self) }
}
