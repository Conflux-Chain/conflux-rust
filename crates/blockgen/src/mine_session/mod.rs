mod state;

use crate::{BlockGenerator, MineWorker, SolutionReceiver};
use cfxcore::pow::ProofOfWorkProblem;
use log::{debug, trace, warn};
use std::{
    ops::Deref,
    thread,
    time::{self, Duration},
};

use state::MineState;

const BLOCK_FORCE_UPDATE_INTERVAL_IN_SECS: u64 = 10;
const BLOCKGEN_LOOP_SLEEP_IN_MILISECS: u64 = 30;

pub(crate) struct MiningSession<'a> {
    bg: &'a BlockGenerator,
    miner: &'a dyn MineWorker,
    solution_rx: SolutionReceiver,
    state: MineState,
}

impl<'a> MiningSession<'a> {
    pub fn new(
        bg: &'a BlockGenerator, miner: &'a dyn MineWorker,
        solution_rx: SolutionReceiver,
    ) -> Self {
        let state =
            MineState::with_capacity(bg.pow_config.pow_problem_window_size);

        MiningSession {
            bg,
            miner,
            solution_rx,
            state,
        }
    }

    pub fn run(mut self) {
        let sleep_duration =
            time::Duration::from_millis(BLOCKGEN_LOOP_SLEEP_IN_MILISECS);

        while self.bg.is_running() {
            // TODO: #transations TBD
            if !self.should_mine() {
                thread::sleep(sleep_duration);
                continue;
            }

            if self.is_mining_block_outdated(&self.state) {
                // Compute new mining task and send to workers
                self.update_mining_task();
            } else {
                // Pull the mining solution
                self.process_pending_solutions();
            }
        }
    }

    fn should_mine(&self) -> bool {
        self.pow_config.test_mode || !self.sync.catch_up_mode()
    }

    /// Check if we need to mine on a new block
    fn is_mining_block_outdated(&self, state: &MineState) -> bool {
        // TODO: update the logic here.

        let Some(block) = state.mining_block() else {
            return true;
        };

        // 1st Check: if the parent block changed
        let best_block_hash = self.consensus.best_block_hash();
        if best_block_hash != *block.block_header.parent_hash() {
            return true;
        }

        // 2nd Check: if the last block is too old, we will generate a new
        // block. Checking transaction updates and referees might be
        // costly and the trade-off is unclear here. It is simple to
        // just enforce a time here.

        const UPDATE_INTERVAL: Duration =
            Duration::from_secs(BLOCK_FORCE_UPDATE_INTERVAL_IN_SECS);
        state.last_assemble_elapsed() > UPDATE_INTERVAL
    }

    fn update_mining_task(&mut self) {
        let next_mining_block = self.assembler.assemble_new_mining_block(None);

        let problem = ProofOfWorkProblem::from_block_header(
            &next_mining_block.block_header,
        );

        self.state.update_job(next_mining_block, problem);
        self.miner.receive_problem(problem);
        trace!("send problem: {:?}", problem);
        self.state.touch_last_assemble();
    }

    /// Pull mining solution from the workers, returns whether a valid solution
    /// is found
    fn process_pending_solutions(&mut self) {
        while let Ok(solution) = self.solution_rx.try_recv() {
            debug!("new solution: {:?}", solution);

            if let Some(mut mined_block) =
                self.state.validate_and_claim_solution(&solution, |p, s| {
                    self.bg.pow.validate(p, s)
                })
            {
                mined_block.block_header.set_nonce(solution.nonce);
                mined_block.block_header.compute_hash();

                self.on_mined_block(mined_block);
                return;
            } else {
                warn!(
                    "Received invalid solution from miner: nonce = {}!",
                    &solution.nonce
                );
            }
        }

        // proof-of-work solution channel is empty without valid solution.

        // We will send out heartbeat because newcomers or
        // disconnected people may lose the previous message
        if !self.pow_config.use_stratum() {
            return;
        }

        if let Some(problem) = self.state.check_for_renotification() {
            debug!("renotify problem: {:?}", problem);
            self.miner.receive_problem(problem);
            self.state.touch_last_notify();
        }
    }
}

impl<'a> Deref for MiningSession<'a> {
    type Target = BlockGenerator;

    fn deref(&self) -> &Self::Target { &*self.bg }
}
